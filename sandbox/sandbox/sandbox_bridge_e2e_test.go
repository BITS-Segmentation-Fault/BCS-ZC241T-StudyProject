package main

import (
	"os"
	"os/exec"
	"strings"
	"testing"

	"sandbox/sandbox/network"
)

// This target is intentionally opt-in: it mutates host links and firewall
// state. CI's privileged job sets SANDBOX_PRIVILEGED_E2E=1 and
// SANDBOX_E2E_REQUIRED=1 so missing prerequisites become failures there.
func TestSandboxPrivilegedBridgeLifecycle(t *testing.T) {
	if os.Getenv("SANDBOX_PRIVILEGED_E2E") != "1" {
		t.Skip("privileged bridge E2E requires SANDBOX_PRIVILEGED_E2E=1")
	}
	if err := network.CheckBridgePrerequisites(); err != nil {
		skipOrFail(t, err.Error())
	}
	sandbox := sandboxTestBinary(t)
	probe := probeTestBinary(t)
	rootfs := makeProbeRootfs(t, probe)
	configPath := writeSandboxConfig(t, rootfs, "bridge", "--exit=0")
	output, err := exec.Command(sandbox, "--config", configPath).CombinedOutput()
	if err != nil {
		if strings.Contains(string(output), "operation not permitted") || strings.Contains(string(output), "permission denied") {
			skipOrFail(t, string(output))
		}
		t.Fatalf("privileged bridge sandbox failed: %v\n%s", err, output)
	}
	if !strings.Contains(string(output), "pid=1") {
		t.Fatalf("bridge probe did not execute in the sandbox: %s", output)
	}
}
