//go:build linux

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"sandbox/sandbox/config"
)

func TestSandboxSeccompBlocksConfiguredSyscalls(t *testing.T) {
	namespacesAvailable(t)
	rootfs := makeProbeRootfs(t, probeTestBinary(t))
	cfg := newSandboxConfig(rootfs, "none", "/bin/probe", "syscall", "mount")
	cfg.BlockedSyscalls = []string{"mount"}
	output, err := exec.Command(sandboxTestBinary(t), "--config", writeSandboxConfig(t, cfg)).CombinedOutput()
	text := string(output)
	if !strings.Contains(text, "syscall-ready") {
		t.Fatalf("blocked-syscall probe did not reach its readiness point: %s", text)
	}
	if strings.Contains(text, "syscall-ok") || strings.Contains(text, "syscall-error=") {
		t.Fatalf("blocked-syscall probe survived or reported a syscall result: %s", text)
	}
	exitErr, ok := err.(*exec.ExitError)
	if !ok || exitErr.ExitCode() != 128+int(syscall.SIGSYS) {
		t.Fatalf("blocked syscall exit = %v, want %d\n%s", err, 128+int(syscall.SIGSYS), text)
	}
}

func TestSandboxDropsEveryCapabilitySet(t *testing.T) {
	namespacesAvailable(t)
	rootfs := makeProbeRootfs(t, probeTestBinary(t))
	cfg := newSandboxConfig(rootfs, "host", "/bin/probe", "capabilities")
	output, err := exec.Command(sandboxTestBinary(t), "--config", writeSandboxConfig(t, cfg)).CombinedOutput()
	if err != nil {
		t.Fatalf("capability probe failed: %v\n%s", err, output)
	}
	for _, name := range []string{"CapEff:", "CapPrm:", "CapInh:", "CapAmb:", "CapBnd:"} {
		line := findLine(string(output), name)
		if line == "" {
			t.Fatalf("capability probe did not report %s: %s", name, output)
		}
		value := strings.TrimSpace(strings.TrimPrefix(line, name))
		if value == "" || strings.Trim(value, "0") != "" {
			t.Fatalf("%s is not empty: %q", name, value)
		}
	}
}

func TestSandboxFilesystemPermissionMatrix(t *testing.T) {
	namespacesAvailable(t)
	probe := probeTestBinary(t)
	rootfs := makeProbeRootfs(t, probe)
	readOnly := newSandboxConfig(rootfs, "host", "/bin/probe", "write-size", "/work/readonly", "1")
	readOnly.ReadOnlyRoot = true
	output, err := exec.Command(sandboxTestBinary(t), "--config", writeSandboxConfig(t, readOnly)).CombinedOutput()
	if err != nil {
		t.Fatalf("read-only root probe failed: %v\n%s", err, output)
	}
	if !strings.Contains(string(output), "write-error=") {
		t.Fatalf("read-only root allowed a write: %s", output)
	}

	hostFile := filepath.Join(t.TempDir(), "bound")
	if err := os.WriteFile(hostFile, []byte("bound-data"), 0600); err != nil {
		t.Fatal(err)
	}
	readOnlyBind := newSandboxConfig(rootfs, "host", "/bin/probe", "read", "/mnt/bound")
	readOnlyBind.BindMounts = []config.BindMount{{HostPath: hostFile, ContainerPath: "/mnt/bound"}}
	output, err = exec.Command(sandboxTestBinary(t), "--config", writeSandboxConfig(t, readOnlyBind)).CombinedOutput()
	if err != nil {
		t.Fatalf("read-only bind probe failed: %v\n%s", err, output)
	}
	if string(output) != "read=bound-data\n" {
		t.Fatalf("read-only bind read returned %q", output)
	}
	readOnlyAppend := newSandboxConfig(rootfs, "host", "/bin/probe", "append", "/mnt/bound", "1")
	readOnlyAppend.BindMounts = []config.BindMount{{HostPath: hostFile, ContainerPath: "/mnt/bound"}}
	output, err = exec.Command(sandboxTestBinary(t), "--config", writeSandboxConfig(t, readOnlyAppend)).CombinedOutput()
	if err != nil || !strings.Contains(string(output), "append-error=") {
		t.Fatalf("read-only bind allowed an append: %v\n%s", err, output)
	}
	data, err := os.ReadFile(hostFile)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "bound-data" {
		t.Fatalf("read-only bind changed host file to %q", data)
	}

	readWrite := newSandboxConfig(rootfs, "host", "/bin/probe", "append", "/mnt/bound", "1")
	readWrite.BindMounts = []config.BindMount{{HostPath: hostFile, ContainerPath: "/mnt/bound", Writable: true}}
	output, err = exec.Command(sandboxTestBinary(t), "--config", writeSandboxConfig(t, readWrite)).CombinedOutput()
	if err != nil || !strings.Contains(string(output), "append-ok") {
		t.Fatalf("writable bind rejected an append: %v\n%s", err, output)
	}
	data, err = os.ReadFile(hostFile)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "bound-data1" {
		t.Fatalf("writable bind changed host file to %q, want bound-data1", data)
	}
}

func TestSandboxDNSMountLeavesRootfsUnchanged(t *testing.T) {
	namespacesAvailable(t)
	rootfs := makeProbeRootfs(t, probeTestBinary(t))
	const original = ""
	if err := os.WriteFile(filepath.Join(rootfs, "etc", "resolv.conf"), []byte(original), 0644); err != nil {
		t.Fatal(err)
	}
	cfg := newSandboxConfig(rootfs, "host", "/bin/probe", "read", "/etc/resolv.conf")
	cfg.DNSServers = []string{"1.1.1.1"}
	output, err := exec.Command(sandboxTestBinary(t), "--config", writeSandboxConfig(t, cfg)).CombinedOutput()
	if err != nil || !strings.Contains(string(output), "read=nameserver 1.1.1.1") {
		t.Fatalf("DNS mount failed: %v\n%s", err, output)
	}
	data, err := os.ReadFile(filepath.Join(rootfs, "etc", "resolv.conf"))
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != original {
		t.Fatalf("source rootfs DNS file changed: %q", data)
	}
}

func TestSandboxResourceLimits(t *testing.T) {
	namespacesAvailable(t)
	rootfs := makeProbeRootfs(t, probeTestBinary(t))
	storage := newSandboxConfig(rootfs, "host", "/bin/probe", "write-size", "/work/large", "2097152")
	storage.FileSizeLimitMB = 1
	output, err := exec.Command(sandboxTestBinary(t), "--config", writeSandboxConfig(t, storage)).CombinedOutput()
	if err != nil || !strings.Contains(string(output), "write-error=") {
		t.Fatalf("storage probe failed: %v\n%s", err, output)
	}

	delegated := newSandboxConfig(rootfs, "host", "/bin/probe", "inspect")
	delegated.MaxProcesses = 32
	output, err = exec.Command(sandboxTestBinary(t), "--config", writeSandboxConfig(t, delegated)).CombinedOutput()
	if err != nil {
		if pidsControllerUnavailable(string(output)) {
			skipOrFail(t, "delegated pids controller is unavailable")
		}
		t.Fatalf("process-limit baseline failed: %v\n%s", err, output)
	}
	if strings.Contains(string(output), "inspect-error=") {
		t.Fatalf("process-limit baseline inspection failed: %s", output)
	}

	delegated.Command = []string{"/bin/probe", "spawn", "64"}
	output, err = exec.Command(sandboxTestBinary(t), "--config", writeSandboxConfig(t, delegated)).CombinedOutput()
	if err != nil || !strings.Contains(string(output), "process-error=") {
		t.Fatalf("process limit did not reject excessive child creation: %v\n%s", err, output)
	}
}

func pidsControllerUnavailable(output string) bool {
	return strings.Contains(output, "cgroup-v2 pids controller is unavailable in the delegated hierarchy") ||
		strings.Contains(output, "cgroup-v2 pids controller is not delegated to the sandbox")
}
