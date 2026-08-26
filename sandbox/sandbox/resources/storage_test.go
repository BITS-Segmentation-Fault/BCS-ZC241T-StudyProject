//go:build linux

package resources

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

const fileSizeLimitHelper = "SANDBOX_FILE_SIZE_LIMIT_HELPER"

const fileSizeLimitSkipPrefix = "SANDBOX_FILE_SIZE_LIMIT_SKIP: "

func TestApplyFileSizeLimitSubprocess(t *testing.T) {
	if os.Getenv(fileSizeLimitHelper) == "1" {
		runFileSizeLimitHelper(t, os.Getenv("SANDBOX_FILE_SIZE_LIMIT_MODE"))
		return
	}

	for _, mode := range []string{"configured", "soft", "hard", "zero"} {
		t.Run(mode, func(t *testing.T) {
			cmd := exec.Command(os.Args[0], "-test.run=^TestApplyFileSizeLimitSubprocess$")
			cmd.Env = append(os.Environ(), fileSizeLimitHelper+"=1", "SANDBOX_FILE_SIZE_LIMIT_MODE="+mode)
			output, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("file-size helper failed: %v\n%s", err, output)
			}
			for _, line := range strings.Split(string(output), "\n") {
				if strings.HasPrefix(line, fileSizeLimitSkipPrefix) {
					t.Skip(strings.TrimSpace(strings.TrimPrefix(line, fileSizeLimitSkipPrefix)))
				}
			}
			if !strings.Contains(string(output), "result=") {
				t.Fatalf("file-size helper returned no result: %s", output)
			}
		})
	}
}

func runFileSizeLimitHelper(t *testing.T, mode string) {
	t.Helper()
	var inherited unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_FSIZE, &inherited); err != nil {
		t.Fatalf("Getrlimit() error = %v", err)
	}
	baseMax := inherited.Max
	if baseMax == unix.RLIM_INFINITY || baseMax > 1<<20 {
		baseMax = 1 << 20
	}
	if baseMax < 4096 {
		fmt.Printf("%sinherited file-size hard limit is too low for the subprocess cases\n", fileSizeLimitSkipPrefix)
		return
	}

	configured := 1
	switch mode {
	case "soft":
		if err := unix.Setrlimit(unix.RLIMIT_FSIZE, &unix.Rlimit{Cur: 4096, Max: baseMax}); err != nil {
			t.Fatalf("set soft limit: %v", err)
		}
	case "hard":
		configured = 2
		if err := unix.Setrlimit(unix.RLIMIT_FSIZE, &unix.Rlimit{Cur: baseMax, Max: baseMax}); err != nil {
			t.Fatalf("set hard limit: %v", err)
		}
	case "zero":
		if err := unix.Setrlimit(unix.RLIMIT_FSIZE, &unix.Rlimit{Cur: 4096, Max: baseMax}); err != nil {
			t.Fatalf("set inherited limit: %v", err)
		}
		configured = 0
	}

	var before unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_FSIZE, &before); err != nil {
		t.Fatalf("Getrlimit() before apply: %v", err)
	}
	if mode == "configured" {
		desired := uint64(configured) * mbToBytes
		if (before.Cur != unix.RLIM_INFINITY && before.Cur < desired) || (before.Max != unix.RLIM_INFINITY && before.Max < desired) {
			fmt.Printf("%sinherited file-size limits are stricter than the configured test ceiling\n", fileSizeLimitSkipPrefix)
			return
		}
	}
	if err := ApplyFileSizeLimit(configured); err != nil {
		t.Fatalf("ApplyFileSizeLimit() error = %v", err)
	}
	var after unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_FSIZE, &after); err != nil {
		t.Fatalf("Getrlimit() after apply: %v", err)
	}

	want := uint64(configured) * mbToBytes
	if before.Cur != unix.RLIM_INFINITY && before.Cur < want {
		want = before.Cur
	}
	if before.Max != unix.RLIM_INFINITY && before.Max < want {
		want = before.Max
	}
	if mode == "zero" {
		if after != before {
			t.Fatalf("zero configuration changed limits from %#v to %#v", before, after)
		}
	} else {
		if mode == "soft" {
			want = 4096
		} else if mode == "hard" {
			want = baseMax
		}
		if after.Cur != want || after.Max != want {
			t.Fatalf("limits = %#v, want both values %d", after, want)
		}
	}
	fmt.Printf("result=%d,%d\n", after.Cur, after.Max)
}

func TestApplyFileSizeLimitRejectsInvalidValues(t *testing.T) {
	if err := ApplyFileSizeLimit(-1); err == nil {
		t.Fatal("negative file-size limit was accepted")
	}
	if strconv.IntSize == 64 {
		if err := ApplyFileSizeLimit(int(^uint64(0) >> 1)); err == nil {
			t.Fatal("overflowing file-size limit was accepted")
		}
	}
}
