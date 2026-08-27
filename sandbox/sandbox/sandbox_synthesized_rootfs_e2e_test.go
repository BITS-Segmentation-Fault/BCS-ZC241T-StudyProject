//go:build linux

package main

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"sandbox/sandbox/config"
)

func TestSandboxSynthesizesMissingRootTargets(t *testing.T) {
	namespacesAvailable(t)
	sandbox := sandboxTestBinary(t)
	probe := probeTestBinary(t)
	for _, readOnlyRoot := range []bool{true, false} {
		name := "writable-root"
		if readOnlyRoot {
			name = "read-only-root"
		}
		t.Run(name, func(t *testing.T) {
			runMinimalRootfsScenario(t, sandbox, probe, readOnlyRoot)
		})
	}
}

func runMinimalRootfsScenario(t *testing.T, sandbox, probe string, readOnlyRoot bool) {
	t.Helper()
	rootfs := t.TempDir()
	bindDirectory := filepath.Join(t.TempDir(), "payload")
	if err := os.Mkdir(bindDirectory, 0755); err != nil {
		t.Fatal(err)
	}
	probeData, err := os.ReadFile(probe)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bindDirectory, "probe"), probeData, 0755); err != nil {
		t.Fatal(err)
	}
	readOnlyFile := filepath.Join(t.TempDir(), "read-only")
	if err := os.WriteFile(readOnlyFile, []byte("bound-data"), 0600); err != nil {
		t.Fatal(err)
	}
	writableFile := filepath.Join(t.TempDir(), "writable")
	if err := os.WriteFile(writableFile, []byte("bound-data"), 0600); err != nil {
		t.Fatal(err)
	}

	base := func(command ...string) config.Config {
		cfg := config.DefaultConfig()
		cfg.RootFSSource = rootfs
		cfg.ReadOnlyRoot = readOnlyRoot
		cfg.WorkingDir = "/work"
		cfg.Command = command
		cfg.BindMounts = []config.BindMount{
			{HostPath: bindDirectory, ContainerPath: "/work"},
			{HostPath: readOnlyFile, ContainerPath: "/license"},
			{HostPath: writableFile, ContainerPath: "/writable", Writable: true},
		}
		cfg.DNSServers = []string{"1.1.1.1"}
		return cfg
	}
	run := func(cfg config.Config) ([]byte, error) {
		return exec.Command(sandbox, "--config", writeSandboxConfig(t, cfg)).CombinedOutput()
	}

	output, err := run(base("/work/probe", "inspect"))
	if err != nil {
		t.Fatalf("minimal rootfs launch failed: %v\n%s", err, output)
	}
	text := string(output)
	if got := findLine(text, "identity="); got != "identity=uid=0 gid=0 pid=2 ppid=1 cwd=/work" {
		t.Fatalf("payload identity = %q\n%s", got, text)
	}
	if findLine(text, "pidns=") == "" || findLine(text, "ready") != "ready" {
		t.Fatalf("synthesized proc mount was not observable: %s", text)
	}

	output, err = run(base("/work/probe", "read", "/license"))
	if err != nil || string(output) != "read=bound-data\n" {
		t.Fatalf("missing regular-file target was not mounted: %v\n%s", err, output)
	}
	output, err = run(base("/work/probe", "read", "/etc/resolv.conf"))
	if err != nil || string(output) != "read=nameserver 1.1.1.1\n\n" {
		t.Fatalf("missing DNS target was not mounted: %v\n%s", err, output)
	}

	output, err = run(base("/work/probe", "append", "/license", "1"))
	if err != nil || !strings.HasPrefix(string(output), "append-error=") {
		t.Fatalf("read-only bind accepted a write: %v\n%s", err, output)
	}
	if data, readErr := os.ReadFile(readOnlyFile); readErr != nil || string(data) != "bound-data" {
		t.Fatalf("read-only source changed: %q, err=%v", data, readErr)
	}

	output, err = run(base("/work/probe", "append", "/writable", "1"))
	if err != nil || string(output) != "append-ok\n" {
		t.Fatalf("writable bind failed: %v\n%s", err, output)
	}
	if data, readErr := os.ReadFile(writableFile); readErr != nil || string(data) != "bound-data1" {
		t.Fatalf("writable source = %q, err=%v", data, readErr)
	}

	output, err = run(base("/work/probe", "write-size", "/root-created", "1"))
	if readOnlyRoot {
		if err != nil || !strings.HasPrefix(string(output), "write-error=") {
			t.Fatalf("read-only root accepted a write: %v\n%s", err, output)
		}
	} else {
		if err != nil || string(output) != "write-ok\n" {
			t.Fatalf("writable root rejected a write: %v\n%s", err, output)
		}
		output, err = run(base("/work/probe", "read", "/root-created"))
		if err != nil || !strings.HasPrefix(string(output), "read-error=") {
			t.Fatalf("writable root change persisted: %v\n%s", err, output)
		}
	}

	for _, path := range []string{"work", "license", "writable", "proc", "etc", "root-created"} {
		if _, statErr := os.Lstat(filepath.Join(rootfs, path)); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("synthesized target %q changed source rootfs: %v", path, statErr)
		}
	}
}
