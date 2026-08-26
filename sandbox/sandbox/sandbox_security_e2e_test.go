//go:build linux

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

type securitySandboxConfig struct {
	readOnlyRoot bool
	seccomp      string
	blocked      []string
	dropCaps     []string
	fileSizeMB   int
	memoryGB     int
	maxProcesses int
	binds        []securityBind
	dns          []string
}

type securityBind struct {
	hostPath      string
	containerPath string
	writable      bool
}

func defaultSecurityConfig() securitySandboxConfig {
	return securitySandboxConfig{
		seccomp: "kill",
	}
}

func TestSandboxSeccompBlocksConfiguredSyscalls(t *testing.T) {
	namespacesAvailable(t)
	rootfs := makeProbeRootfs(t, probeTestBinary(t))
	cfg := defaultSecurityConfig()
	cfg.seccomp = "kill"
	cfg.blocked = []string{"mount"}
	output, err := runSecurityProbe(t, rootfs, "none", []string{"--syscall=mount"}, cfg)
	if err == nil {
		t.Fatalf("blocked syscall unexpectedly succeeded: %s", output)
	}
	if unsupportedSandboxOutput(output) {
		skipOrFail(t, output)
	}
	if !strings.Contains(output, "Handing off") {
		t.Fatalf("blocked-syscall probe did not reach the payload: %s", output)
	}
}

func TestSandboxDropsEveryCapabilitySet(t *testing.T) {
	namespacesAvailable(t)
	rootfs := makeProbeRootfs(t, probeTestBinary(t))
	cfg := defaultSecurityConfig()
	cfg.dropCaps = []string{"ALL"}
	output, err := runSecurityProbe(t, rootfs, "host", []string{"--capabilities"}, cfg)
	if err != nil {
		if unsupportedSandboxOutput(output) {
			skipOrFail(t, output)
		}
		t.Fatalf("capability probe failed: %v\n%s", err, output)
	}
	for _, name := range []string{"CapEff:", "CapPrm:", "CapInh:", "CapAmb:", "CapBnd:"} {
		line := findLine(output, name)
		if line == "" {
			t.Fatalf("capability probe did not report %s: %s", name, output)
		}
		value := strings.TrimSpace(strings.TrimPrefix(line, name))
		if value == "" || strings.Trim(value, "0") != "" {
			t.Fatalf("%s is not empty: %q", name, value)
		}
	}
}

func TestSandboxNoneModeDeniesNetworkAccess(t *testing.T) {
	namespacesAvailable(t)
	rootfs := makeProbeRootfs(t, probeTestBinary(t))
	cfg := defaultSecurityConfig()
	for _, test := range []struct {
		name string
		arg  string
		want string
	}{
		{name: "tcp", arg: "--tcp=127.0.0.1:9", want: "tcp-error="},
		{name: "udp", arg: "--udp=127.0.0.1:9", want: "udp-error="},
		{name: "dns", arg: "--dns=example.invalid", want: "dns-error="},
	} {
		t.Run(test.name, func(t *testing.T) {
			output, err := runSecurityProbe(t, rootfs, "none", []string{test.arg}, cfg)
			if err != nil {
				if unsupportedSandboxOutput(output) {
					skipOrFail(t, output)
				}
				t.Fatalf("network probe failed: %v\n%s", err, output)
			}
			if !strings.Contains(output, test.want) {
				t.Fatalf("none-mode network policy was not enforced: wanted %q in %s", test.want, output)
			}
		})
	}
}

func TestSandboxFilesystemPermissionMatrix(t *testing.T) {
	namespacesAvailable(t)
	probe := probeTestBinary(t)
	rootfs := makeProbeRootfs(t, probe)
	readOnly := defaultSecurityConfig()
	readOnly.readOnlyRoot = true
	output, err := runSecurityProbe(t, rootfs, "host", []string{"--write-bytes=/work/readonly:1"}, readOnly)
	if err != nil {
		if unsupportedSandboxOutput(output) {
			skipOrFail(t, output)
		}
		t.Fatalf("read-only root probe failed: %v\n%s", err, output)
	}
	if !strings.Contains(output, "write-error=") {
		t.Fatalf("read-only root allowed a write: %s", output)
	}

	hostFile := filepath.Join(t.TempDir(), "bound")
	if err := os.WriteFile(hostFile, []byte("bound-data"), 0600); err != nil {
		t.Fatal(err)
	}
	readOnlyBind := defaultSecurityConfig()
	readOnlyBind.binds = []securityBind{{hostPath: hostFile, containerPath: "/mnt/bound"}}
	output, err = runSecurityProbe(t, rootfs, "host", []string{"--read=/mnt/bound", "--write-bytes=/mnt/bound:1"}, readOnlyBind)
	if err != nil {
		if unsupportedSandboxOutput(output) {
			skipOrFail(t, output)
		}
		t.Fatalf("read-only bind probe failed: %v\n%s", err, output)
	}
	if !strings.Contains(output, "read=bound-data") || !strings.Contains(output, "write-error=") {
		t.Fatalf("read-only bind matrix failed: %s", output)
	}

	readWrite := defaultSecurityConfig()
	readWrite.binds = []securityBind{{hostPath: hostFile, containerPath: "/mnt/bound", writable: true}}
	output, err = runSecurityProbe(t, rootfs, "host", []string{"--write-bytes=/mnt/bound:1"}, readWrite)
	if err != nil {
		if unsupportedSandboxOutput(output) {
			skipOrFail(t, output)
		}
		t.Fatalf("read-write bind probe failed: %v\n%s", err, output)
	}
	if !strings.Contains(output, "write-ok") {
		t.Fatalf("read-write bind rejected a write: %s", output)
	}
}

func TestSandboxResourceLimits(t *testing.T) {
	namespacesAvailable(t)
	rootfs := makeProbeRootfs(t, probeTestBinary(t))
	storage := defaultSecurityConfig()
	storage.fileSizeMB = 1
	output, err := runSecurityProbe(t, rootfs, "host", []string{"--write-bytes=/work/large:2097152"}, storage)
	if err != nil {
		if unsupportedSandboxOutput(output) {
			skipOrFail(t, output)
		}
		t.Fatalf("storage probe failed: %v\n%s", err, output)
	}
	if !strings.Contains(output, "write-error=") {
		t.Fatalf("file-size limit allowed a file over the configured ceiling: %s", output)
	}

	delegated := defaultSecurityConfig()
	// The pids controller counts Go runtime tasks as well as processes. First
	// prove that the selected ceiling admits the sandbox baseline, then ask the
	// payload to create substantially more children than that ceiling allows.
	delegated.maxProcesses = 32
	output, err = runSecurityProbe(t, rootfs, "host", nil, delegated)
	if err != nil || strings.Contains(output, "resource limits cannot be provisioned") {
		if strings.Contains(output, "cgroup") || unsupportedSandboxOutput(output) {
			skipOrFail(t, output)
		}
		t.Fatalf("process-limit preflight failed unexpectedly: %v\n%s", err, output)
	}
	if strings.Contains(output, "process-error=") {
		t.Fatalf("process limit rejected the sandbox runtime baseline: %s", output)
	}
	output, err = runSecurityProbe(t, rootfs, "host", []string{"--spawn-processes=64"}, delegated)
	if err != nil || strings.Contains(output, "resource limits cannot be provisioned") {
		if strings.Contains(output, "cgroup") || unsupportedSandboxOutput(output) {
			skipOrFail(t, output)
		}
		t.Fatalf("process-limit preflight failed unexpectedly: %v\n%s", err, output)
	}
	if !strings.Contains(output, "process-error=") {
		t.Fatalf("process limit did not reject excessive child creation: %s", output)
	}
}

func runSecurityProbe(t *testing.T, rootfs, mode string, args []string, options securitySandboxConfig) (string, error) {
	t.Helper()
	configPath := writeSecuritySandboxConfig(t, rootfs, mode, args, options)
	output, err := exec.Command(sandboxTestBinary(t), "--config", configPath).CombinedOutput()
	return string(output), err
}

func writeSecuritySandboxConfig(t *testing.T, rootfs, mode string, args []string, options securitySandboxConfig) string {
	t.Helper()
	quoteList := func(values []string) string {
		quoted := make([]string, 0, len(values))
		for _, value := range values {
			quoted = append(quoted, strconv.Quote(value))
		}
		return "[" + strings.Join(quoted, ", ") + "]"
	}
	command := append([]string{"/bin/probe"}, args...)
	lines := []string{
		"command: " + quoteList(command),
		"env_vars: [\"PATH=/bin:/usr/bin\"]",
		fmt.Sprintf("read_only_root: %t", options.readOnlyRoot),
		"blocked_syscall_action: " + options.seccomp,
		"blocked_syscalls: " + quoteList(options.blocked),
		"drop_capabilities: " + quoteList(options.dropCaps),
		fmt.Sprintf("file_size_limit_mb: %d", options.fileSizeMB),
		"cpu_limit_percent: 0",
		fmt.Sprintf("memory_limit_gb: %d", options.memoryGB),
		fmt.Sprintf("max_processes: %d", options.maxProcesses),
		"network_mode: " + mode,
		"working_dir: /work",
		"rootfs_source: " + strconv.Quote(rootfs),
		"dns_servers: " + quoteList(options.dns),
	}
	if len(options.binds) == 0 {
		lines = append(lines, "bind_mounts: []")
	} else {
		lines = append(lines, "bind_mounts:")
		for _, bind := range options.binds {
			lines = append(lines,
				"  - host_path: "+strconv.Quote(bind.hostPath),
				"    container_path: "+strconv.Quote(bind.containerPath))
			if bind.writable {
				lines = append(lines, "    writable: true")
			}
		}
	}
	path := filepath.Join(t.TempDir(), "sandbox.yaml")
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func findLine(output, prefix string) string {
	for _, line := range strings.Split(output, "\n") {
		if strings.HasPrefix(line, prefix) {
			return line
		}
	}
	return ""
}
