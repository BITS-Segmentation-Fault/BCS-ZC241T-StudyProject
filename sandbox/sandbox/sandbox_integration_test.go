package main

import (
	"os/exec"
	"strings"
	"testing"
)

func TestSandboxBinaryRejectsInternalChildWithoutNamespace(t *testing.T) {
	binary := sandboxTestBinary(t)
	output, err := exec.Command(binary, "--internal-child").CombinedOutput()
	if err == nil || !strings.Contains(string(output), "requires PID 1") {
		t.Fatalf("internal child invocation was accepted: err=%v output=%s", err, output)
	}
}

func TestSandboxBinaryRejectsInternalMarkerAfterPublicArguments(t *testing.T) {
	binary := sandboxTestBinary(t)
	output, err := exec.Command(binary, "--network-mode", "host", "--internal-child").CombinedOutput()
	if err == nil || !strings.Contains(string(output), "internal child marker must be the first argument") {
		t.Fatalf("late internal marker was accepted: err=%v output=%s", err, output)
	}
}
