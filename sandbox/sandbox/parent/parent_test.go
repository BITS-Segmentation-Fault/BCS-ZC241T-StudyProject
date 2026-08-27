//go:build linux

package parent

import (
	"bytes"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"syscall"
	"testing"

	"sandbox/sandbox/config"
	"sandbox/sandbox/rootfs"
)

func TestWaitForChild_ReturnsExitStatus(t *testing.T) {
	tests := []struct {
		name    string
		command []string
		want    int
	}{
		{name: "exit", command: []string{"/bin/sh", "-c", "exit 7"}, want: 7},
		{name: "signal", command: []string{"/bin/sh", "-c", "kill -TERM $$"}, want: 143},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := exec.Command(tt.command[0], tt.command[1:]...)
			if err := cmd.Start(); err != nil {
				t.Fatalf("start child: %v", err)
			}
			if got := waitForChild(cmd, nil); got != tt.want {
				t.Fatalf("waitForChild() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestProgressRendererSilenceAndTTYOutput(t *testing.T) {
	var output bytes.Buffer
	silent := &progressRenderer{out: &output}
	silent.report(rootfs.ProgressEvent{Phase: rootfs.ProgressDownloadingArchive, Current: 1, Total: 2})
	silent.finish()
	if output.Len() != 0 {
		t.Fatalf("non-TTY progress output = %q, want empty", output.String())
	}

	for _, test := range []struct {
		name    string
		current int64
		total   int64
		wantBar string
	}{
		{name: "zero", current: 0, total: 100, wantBar: "[>...................]"},
		{name: "partial", current: 50, total: 100, wantBar: "[==========>.........]"},
		{name: "complete", current: 100, total: 100, wantBar: "[====================]"},
		{name: "over-reported", current: 150, total: 100, wantBar: "[====================]"},
	} {
		t.Run(test.name, func(t *testing.T) {
			output.Reset()
			renderer := &progressRenderer{out: &output, tty: true}
			renderer.report(rootfs.ProgressEvent{Phase: rootfs.ProgressDownloadingArchive, Current: test.current, Total: test.total})
			renderer.finish()
			if !strings.Contains(output.String(), test.wantBar) {
				t.Fatalf("TTY progress output = %q, want bar %q", output.String(), test.wantBar)
			}
			if test.current == 50 && !strings.Contains(output.String(), "50%") {
				t.Fatalf("TTY progress output = %q, want percentage", output.String())
			}
			if !strings.Contains(output.String(), "\n") {
				t.Fatalf("TTY progress output = %q, want line finish", output.String())
			}
		})
	}

	output.Reset()
	renderer := &progressRenderer{out: &output, tty: true}
	renderer.report(rootfs.ProgressEvent{Phase: rootfs.ProgressDownloadingArchive, Current: 1, Total: 0})
	renderer.finish()
	if strings.Contains(output.String(), "%") || strings.Contains(output.String(), "NaN") {
		t.Fatalf("unknown-total progress output = %q, want no percentage", output.String())
	}
}

func TestWaitForChild_ForwardsSignalsToNamespaceInit(t *testing.T) {
	cmd := exec.Command("/bin/sleep", "30")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start child: %v", err)
	}
	signals := make(chan os.Signal, 1)
	signals <- syscall.SIGTERM
	if got := waitForChild(cmd, signals); got != 128+int(syscall.SIGTERM) {
		t.Fatalf("waitForChild() = %d, want %d", got, 128+int(syscall.SIGTERM))
	}
}

func TestSnapshotEnvironment(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.EnvVars = []string{"PATH=/custom", "PROBE_VALUE=explicit"}
	cfg.EnvWhitelist = []string{"PROBE_VALUE", "ALLOWED"}
	snapshot := snapshotEnvironment(cfg, []string{
		"PATH=/host",
		"PROBE_VALUE=host",
		"ALLOWED=host-value",
		"SECRET=should-not-cross",
	})
	if got, want := snapshot.EnvVars, []string{"PATH=/custom", "PROBE_VALUE=explicit", "ALLOWED=host-value"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("snapshot EnvVars = %#v, want %#v", got, want)
	}
	if snapshot.EnvWhitelist != nil {
		t.Fatalf("snapshot EnvWhitelist = %#v, want nil", snapshot.EnvWhitelist)
	}
	snapshot.EnvVars[0] = "PATH=/changed"
	if cfg.EnvVars[0] != "PATH=/custom" {
		t.Fatalf("snapshot shares EnvVars storage with input")
	}
	if got, want := internalChildEnvironment(snapshot.EnvVars), []string{"PATH=/changed"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("internal child environment = %#v, want %#v", got, want)
	}
	if got := internalChildEnvironment([]string{"PROBE_VALUE=host", "SECRET=should-not-cross"}); got == nil || len(got) != 0 {
		t.Fatalf("internal child environment without PATH = %#v, want non-nil empty slice", got)
	}
}
