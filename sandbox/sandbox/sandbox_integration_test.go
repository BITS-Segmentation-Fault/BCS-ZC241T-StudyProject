package main

import (
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestSandboxBinaryRejectsUnknownFlag(t *testing.T) {
	binary := sandboxTestBinary(t)
	output, err := exec.Command(binary, "--not-a-sandbox-option").CombinedOutput()
	if err == nil {
		t.Fatal("sandbox unexpectedly accepted an unknown flag")
	}
	if !strings.Contains(string(output), "flag provided but not defined") {
		t.Fatalf("unexpected CLI error: %s", output)
	}
}

func TestSandboxBinaryDiscoversConfigAfterOptions(t *testing.T) {
	binary := sandboxTestBinary(t)
	config := filepath.Join(t.TempDir(), "sandbox.yaml")
	if err := writeMinimalConfig(config); err != nil {
		t.Fatal(err)
	}
	output, err := exec.Command(binary, "--verbose", "--config", config).CombinedOutput()
	if err == nil {
		t.Fatal("sandbox unexpectedly started without a command")
	}
	if !strings.Contains(string(output), "either binary_path or command must be provided") {
		t.Fatalf("config-ordering error was lost: %s", output)
	}
}

func TestSandboxBinaryRejectsPublicInternalOptions(t *testing.T) {
	binary := sandboxTestBinary(t)
	output, err := exec.Command(binary, "--child", "echo").CombinedOutput()
	if err == nil || !strings.Contains(string(output), "flag provided but not defined") {
		t.Fatalf("public child option was not rejected: err=%v output=%s", err, output)
	}
}

func writeMinimalConfig(path string) error {
	return writeFile(path, "network_mode: host\ncpu_limit_percent: 0\nmemory_limit_gb: 0\nmax_processes: 0\n")
}
