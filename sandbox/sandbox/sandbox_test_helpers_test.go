package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func sandboxTestBinary(t *testing.T) string {
	t.Helper()
	if binary := os.Getenv("SANDBOX_BINARY"); binary != "" {
		return binary
	}
	if binary := findRunfileAny("sandbox/sandbox/sandbox", "sandbox/sandbox/sandbox_/sandbox"); binary != "" {
		return binary
	}
	return buildGoBinary(t, ".", "sandbox")
}

func probeTestBinary(t *testing.T) string {
	t.Helper()
	if binary := os.Getenv("SANDBOX_PROBE_BINARY"); binary != "" {
		return binary
	}
	if binary := findRunfileAny("sandbox/sandbox/testprobe", "sandbox/sandbox/testprobe_/testprobe"); binary != "" {
		return binary
	}
	return buildGoBinary(t, "./testprobe", "testprobe")
}

func buildGoBinary(t *testing.T, packagePath, name string) string {
	t.Helper()
	_, sourceFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate sandbox test source")
	}
	moduleDir := filepath.Dir(sourceFile)
	goTool := os.Getenv("GO")
	if goTool == "" {
		goTool, _ = exec.LookPath("go")
	}
	if goTool == "" {
		candidate := filepath.Join(runtime.GOROOT(), "bin", "go")
		if _, err := os.Stat(candidate); err == nil {
			goTool = candidate
		}
	}
	if goTool == "" {
		t.Fatalf("cannot build %s: the go command is unavailable", name)
	}
	out := filepath.Join(t.TempDir(), name)
	cmd := exec.Command(goTool, "build", "-o", out, packagePath)
	cmd.Dir = moduleDir
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build %s: %v\n%s", name, err, output)
	}
	return out
}

func findRunfile(name string) string {
	return findRunfileAny(name)
}

func findRunfileAny(names ...string) string {
	var candidates []string
	for _, name := range names {
		candidates = append(candidates, name)
	}
	for _, rootVar := range []string{"RUNFILES_DIR", "TEST_SRCDIR"} {
		if root := os.Getenv(rootVar); root != "" {
			for _, name := range names {
				candidates = append(candidates, filepath.Join(root, name), filepath.Join(root, "_main", name))
			}
		}
	}
	for _, candidate := range candidates {
		if info, err := os.Stat(candidate); err == nil && info.Mode().IsRegular() {
			return candidate
		}
	}
	if manifest := os.Getenv("RUNFILES_MANIFEST_FILE"); manifest != "" {
		file, err := os.Open(manifest)
		if err == nil {
			defer file.Close()
			scanner := bufio.NewScanner(file)
			for scanner.Scan() {
				fields := strings.SplitN(scanner.Text(), " ", 2)
				if len(fields) == 2 && anySuffix(fields[0], names) {
					if info, statErr := os.Stat(fields[1]); statErr == nil && info.Mode().IsRegular() {
						return fields[1]
					}
				}
			}
		}
	}
	return ""
}

func anySuffix(value string, suffixes []string) bool {
	for _, suffix := range suffixes {
		if value == suffix || strings.HasSuffix(value, "/"+suffix) {
			return true
		}
	}
	return false
}

func skipOrFail(t *testing.T, reason string) {
	t.Helper()
	if value := os.Getenv("SANDBOX_E2E_REQUIRED"); value == "1" || strings.EqualFold(value, "true") {
		t.Fatalf("required sandbox prerequisite is unavailable: %s", reason)
	}
	t.Skip(reason)
}

func writeFile(path, contents string) error {
	return os.WriteFile(path, []byte(contents), 0600)
}

func namespacesAvailable(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("unshare"); err != nil {
		skipOrFail(t, "unshare is unavailable for namespace preflight")
		return
	}
	if err := exec.Command("unshare", "-Ur", "true").Run(); err != nil {
		skipOrFail(t, fmt.Sprintf("user namespaces are unavailable: %v", err))
	}
}
