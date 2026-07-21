//go:build linux

package parent

import (
	"os/exec"
	"testing"

	"sandbox/sandbox/config"
)

func TestWaitForChild_ReturnsChildExitCode(t *testing.T) {
	cmd := exec.Command("/bin/sh", "-c", "exit 7")
	if err := cmd.Start(); err != nil {
		t.Fatalf("start child: %v", err)
	}

	if got := waitForChild(cmd, nil, config.DefaultConfig(), nil); got != 7 {
		t.Fatalf("waitForChild() = %d, want 7", got)
	}
}

func TestWaitForChild_ReturnsSuccess(t *testing.T) {
	cmd := exec.Command("/bin/sh", "-c", "exit 0")
	if err := cmd.Start(); err != nil {
		t.Fatalf("start child: %v", err)
	}

	if got := waitForChild(cmd, nil, config.DefaultConfig(), nil); got != 0 {
		t.Fatalf("waitForChild() = %d, want 0", got)
	}
}

func TestWaitForChild_ReturnsSignalStatus(t *testing.T) {
	cmd := exec.Command("/bin/sh", "-c", "kill -TERM $$")
	if err := cmd.Start(); err != nil {
		t.Fatalf("start child: %v", err)
	}
	if got := waitForChild(cmd, nil, config.DefaultConfig(), nil); got != 143 {
		t.Fatalf("waitForChild() = %d, want 143", got)
	}
}
