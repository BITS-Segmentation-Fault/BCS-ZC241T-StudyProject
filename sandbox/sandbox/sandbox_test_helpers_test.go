package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"

	"gopkg.in/yaml.v3"
	"sandbox/sandbox/config"
	"sandbox/sandbox/network"
)

var testBinaries struct {
	sync.Mutex
	sandbox string
	probe   string
}

var testBinaryDir string

func TestMain(m *testing.M) {
	directory, err := os.MkdirTemp("", "sandbox-test-binaries-")
	if err != nil {
		fmt.Fprintf(os.Stderr, "create test binary directory: %v\n", err)
		os.Exit(1)
	}
	testBinaryDir = directory
	status := m.Run()
	if err := os.RemoveAll(directory); err != nil {
		fmt.Fprintf(os.Stderr, "remove test binary directory: %v\n", err)
		if status == 0 {
			status = 1
		}
	}
	os.Exit(status)
}

func sandboxTestBinary(t *testing.T) string {
	t.Helper()
	if binary := os.Getenv("SANDBOX_BINARY"); binary != "" {
		return binary
	}
	if binary := findRunfileAny("sandbox/sandbox/sandbox", "sandbox/sandbox/sandbox_/sandbox"); binary != "" {
		return binary
	}
	testBinaries.Lock()
	defer testBinaries.Unlock()
	if testBinaries.sandbox == "" {
		testBinaries.sandbox = buildGoBinary(t, ".", "sandbox")
	}
	return testBinaries.sandbox
}

func probeTestBinary(t *testing.T) string {
	t.Helper()
	if binary := os.Getenv("SANDBOX_PROBE_BINARY"); binary != "" {
		return binary
	}
	if binary := findRunfileAny("sandbox/sandbox/testprobe", "sandbox/sandbox/testprobe_/testprobe"); binary != "" {
		return binary
	}
	testBinaries.Lock()
	defer testBinaries.Unlock()
	if testBinaries.probe == "" {
		testBinaries.probe = buildGoBinary(t, "./testprobe", "testprobe")
	}
	return testBinaries.probe
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
	if testBinaryDir == "" {
		t.Fatal("test binary directory is not initialized")
	}
	out := filepath.Join(testBinaryDir, name)
	cmd := exec.Command(goTool, "build", "-o", out, packagePath)
	cmd.Dir = moduleDir
	cmd.Env = withEnvironment(os.Environ(), "CGO_ENABLED", "0")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build %s: %v\n%s", name, err, output)
	}
	return out
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

func findLine(output, prefix string) string {
	for _, line := range strings.Split(output, "\n") {
		if strings.HasPrefix(line, prefix) {
			return line
		}
	}
	return ""
}

var supervisedPayloadIdentityPattern = regexp.MustCompile(`^identity=uid=([0-9]+) gid=([0-9]+) pid=([0-9]+) ppid=([0-9]+) cwd=(.*)$`)

func requireSupervisedPayloadIdentity(t *testing.T, output, wantWorkingDir string) {
	t.Helper()
	line := findLine(output, "identity=")
	matches := supervisedPayloadIdentityPattern.FindStringSubmatch(line)
	if len(matches) != 6 {
		t.Fatalf("payload identity = %q, want a complete identity line", line)
	}
	uid, err := strconv.Atoi(matches[1])
	if err != nil {
		t.Fatalf("payload UID in %q is invalid: %v", line, err)
	}
	gid, err := strconv.Atoi(matches[2])
	if err != nil {
		t.Fatalf("payload GID in %q is invalid: %v", line, err)
	}
	pid, err := strconv.Atoi(matches[3])
	if err != nil {
		t.Fatalf("payload PID in %q is invalid: %v", line, err)
	}
	ppid, err := strconv.Atoi(matches[4])
	if err != nil {
		t.Fatalf("payload parent PID in %q is invalid: %v", line, err)
	}
	if uid != 0 || gid != 0 || ppid != 1 || pid <= 1 || matches[5] != wantWorkingDir {
		t.Fatalf("payload identity = %q, want uid=0 gid=0 pid>1 ppid=1 cwd=%s", line, wantWorkingDir)
	}
}

func skipOrFail(t *testing.T, reason string) {
	t.Helper()
	if value := os.Getenv("SANDBOX_E2E_REQUIRED"); value == "1" || strings.EqualFold(value, "true") {
		t.Fatalf("required sandbox prerequisite is unavailable: %s", reason)
	}
	t.Skip(reason)
}

func makeProbeRootfs(t *testing.T, probe string) string {
	t.Helper()
	rootfs := filepath.Join(t.TempDir(), "rootfs")
	for _, directory := range []string{"bin", "etc", "mnt", "proc", "work"} {
		if err := os.MkdirAll(filepath.Join(rootfs, directory), 0755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(rootfs, "etc", "resolv.conf"), nil, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(rootfs, "mnt", "bound"), nil, 0644); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(probe)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(rootfs, "bin", "probe"), data, 0755); err != nil {
		t.Fatal(err)
	}
	return rootfs
}

func newSandboxConfig(rootfs, mode string, command ...string) config.Config {
	cfg := config.DefaultConfig()
	cfg.Command = append([]string(nil), command...)
	cfg.EnvVars = []string{"PATH=/bin:/usr/bin", "PROBE_VALUE=probe-value"}
	cfg.RootFSSource = rootfs
	cfg.ReadOnlyRoot = false
	cfg.WorkingDir = "/work"
	cfg.NetworkMode = network.NetworkMode(mode)
	return cfg
}

func writeSandboxConfig(t *testing.T, cfg config.Config) string {
	t.Helper()
	data, err := yaml.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "sandbox.yaml")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func namespaceLink(t *testing.T, path string) string {
	t.Helper()
	value, err := os.Readlink(path)
	if err != nil {
		t.Fatal(err)
	}
	return value
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

func withEnvironment(environment []string, key, value string) []string {
	prefix := key + "="
	result := make([]string, 0, len(environment)+1)
	set := false
	for _, entry := range environment {
		if strings.HasPrefix(entry, prefix) {
			if !set {
				result = append(result, prefix+value)
				set = true
			}
			continue
		}
		result = append(result, entry)
	}
	if !set {
		result = append(result, prefix+value)
	}
	return result
}
