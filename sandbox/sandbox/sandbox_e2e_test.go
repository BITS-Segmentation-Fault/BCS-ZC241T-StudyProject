package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestSandboxRootlessHostAndNone(t *testing.T) {
	namespacesAvailable(t)
	sandbox := sandboxTestBinary(t)
	probe := probeTestBinary(t)
	for _, mode := range []string{"host", "none"} {
		t.Run(mode, func(t *testing.T) {
			rootfs := makeProbeRootfs(t, probe)
			sentinel := filepath.Join(t.TempDir(), "host-only-sentinel")
			if err := os.WriteFile(sentinel, []byte("host-secret"), 0600); err != nil {
				t.Fatal(err)
			}
			configPath := writeSandboxConfig(t, rootfs, mode, fmt.Sprintf("--read=%s", sentinel))
			output, err := exec.Command(sandbox, "--config", configPath).CombinedOutput()
			if err != nil {
				if strings.Contains(string(output), "operation not permitted") || strings.Contains(string(output), "permission denied") {
					skipOrFail(t, string(output))
				}
				t.Fatalf("sandbox %s execution failed: %v\n%s", mode, err, output)
			}
			text := string(output)
			for _, want := range []string{"uid=0", "gid=0", "pid=1", "cwd=/work", "env=probe-value", "read-error"} {
				if !strings.Contains(text, want) {
					t.Fatalf("sandbox %s output missing %q:\n%s", mode, want, text)
				}
			}
		})
	}
}

func TestSandboxPreservesExitAndSignalStatus(t *testing.T) {
	namespacesAvailable(t)
	sandbox := sandboxTestBinary(t)
	probe := probeTestBinary(t)
	rootfs := makeProbeRootfs(t, probe)

	exitConfig := writeSandboxConfig(t, rootfs, "host", "--exit=7")
	command := exec.Command(sandbox, "--config", exitConfig)
	output, err := command.CombinedOutput()
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != 7 {
		if unsupportedSandboxOutput(string(output)) {
			skipOrFail(t, string(output))
		}
		t.Fatalf("sandbox did not preserve exit code: err=%v output=%s", err, output)
	}

	for _, signal := range []syscall.Signal{syscall.SIGINT, syscall.SIGHUP, syscall.SIGTERM, syscall.SIGQUIT} {
		t.Run(signal.String(), func(t *testing.T) {
			signalConfig := writeSandboxConfig(t, rootfs, "host", "--sleep=30")
			running := exec.Command(sandbox, "--config", signalConfig)
			var signalOutput bytes.Buffer
			running.Stdout = &signalOutput
			running.Stderr = &signalOutput
			if err := running.Start(); err != nil {
				t.Fatal(err)
			}
			time.Sleep(250 * time.Millisecond)
			if err := running.Process.Signal(signal); err != nil {
				t.Fatal(err)
			}
			err := running.Wait()
			expected := 128 + int(signal)
			if !errors.As(err, &exitErr) || exitErr.ExitCode() != expected {
				if unsupportedSandboxOutput(signalOutput.String()) {
					skipOrFail(t, signalOutput.String())
				}
				t.Fatalf("sandbox did not preserve %s status: err=%v output=%s", signal, err, signalOutput.String())
			}
		})
	}
}

func unsupportedSandboxOutput(output string) bool {
	return strings.Contains(output, "operation not permitted") || strings.Contains(output, "permission denied")
}

func makeProbeRootfs(t *testing.T, probe string) string {
	t.Helper()
	rootfs := filepath.Join(t.TempDir(), "rootfs")
	if err := os.MkdirAll(filepath.Join(rootfs, "bin", "work"), 0755); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(probe)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(rootfs, "bin", "probe"), data, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(rootfs, "work"), 0755); err != nil {
		t.Fatal(err)
	}
	return rootfs
}

func writeSandboxConfig(t *testing.T, rootfs, mode, probeArg string) string {
	t.Helper()
	configPath := filepath.Join(t.TempDir(), "sandbox.yaml")
	contents := fmt.Sprintf(`command: [/bin/probe, %q]
env_vars: [PROBE_VALUE=probe-value]
env_whitelist: []
read_only_root: false
blocked_syscall_action: kill
blocked_syscalls: []
drop_capabilities: []
file_size_limit_mb: 0
memory_limit_gb: 0
max_processes: 0
network_mode: %s
working_dir: /work
rootfs_source: %q
`, probeArg, mode, rootfs)
	if err := os.WriteFile(configPath, []byte(contents), 0600); err != nil {
		t.Fatal(err)
	}
	return configPath
}
