//go:build linux

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// This test is opt-in because it downloads the reviewed Alpine archive into
// the user's cache on its first run. It also verifies that a none-mode launch
// performs host-side managed-rootfs provisioning before entering the sandbox.
// CI's managed-rootfs job sets both SANDBOX_MANAGED_ROOTFS_E2E=1 and
// SANDBOX_E2E_REQUIRED=1.
func TestSandboxManagedRootFSDefault(t *testing.T) {
	if os.Getenv("SANDBOX_MANAGED_ROOTFS_E2E") != "1" {
		t.Skip("managed-rootfs E2E requires SANDBOX_MANAGED_ROOTFS_E2E=1")
	}
	namespacesAvailable(t)

	sandbox := sandboxTestBinary(t)
	cacheDir := t.TempDir()
	managedRoot := filepath.Join(cacheDir, "bcs-zc241t-sandbox", "rootfs", "alpine", "3.24.1")
	if _, err := os.Stat(managedRoot); !os.IsNotExist(err) {
		t.Fatalf("managed-rootfs E2E cache was not fresh: %v", err)
	}

	run := func(extra ...string) ([]byte, error) {
		command := exec.Command(sandbox, "--network-mode=none", "--", "/bin/echo", "hello world")
		command.Env = withEnvironment(os.Environ(), "XDG_CACHE_HOME", cacheDir)
		for _, entry := range extra {
			key, value, ok := strings.Cut(entry, "=")
			if ok {
				command.Env = withEnvironment(command.Env, key, value)
			}
		}
		return command.CombinedOutput()
	}

	output, err := run()
	if err != nil {
		if unsupportedSandboxOutput(string(output)) {
			skipOrFail(t, string(output))
		}
		t.Fatalf("managed-rootfs sandbox failed: %v\n%s", err, output)
	}
	if !strings.Contains(string(output), "hello world") {
		t.Fatalf("managed-rootfs payload output missing: %s", output)
	}
	if _, err := os.Stat(managedRoot); err != nil {
		t.Fatalf("first launch did not publish the managed rootfs: %v", err)
	}

	// A valid cache must be reusable without contacting Alpine. These invalid
	// proxy settings make an accidental second download fail immediately.
	output, err = run("HTTPS_PROXY=http://127.0.0.1:1", "HTTP_PROXY=http://127.0.0.1:1", "ALL_PROXY=http://127.0.0.1:1", "NO_PROXY=")
	if err != nil {
		t.Fatalf("offline managed-rootfs launch failed: %v\n%s", err, output)
	}
}
