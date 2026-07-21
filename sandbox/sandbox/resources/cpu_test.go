//go:build linux

package resources

import (
	"os"
	"path/filepath"
	"testing"
)

func TestConfigureCPULimit(t *testing.T) {
	path := t.TempDir()
	if err := os.WriteFile(filepath.Join(path, "cpu.max"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(path, "cgroup.procs"), nil, 0600); err != nil {
		t.Fatal(err)
	}

	if err := configureCPULimit(path, 1234, 25); err != nil {
		t.Fatalf("configureCPULimit() error = %v", err)
	}

	quota, err := os.ReadFile(filepath.Join(path, "cpu.max"))
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(quota), "25000 100000\n"; got != want {
		t.Fatalf("cpu.max = %q, want %q", got, want)
	}
	procs, err := os.ReadFile(filepath.Join(path, "cgroup.procs"))
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(procs), "1234\n"; got != want {
		t.Fatalf("cgroup.procs = %q, want %q", got, want)
	}
}

func TestApplyCPULimitDisabled(t *testing.T) {
	cleanup, err := ApplyCPULimit(1234, 0)
	if err != nil {
		t.Fatalf("ApplyCPULimit() error = %v", err)
	}
	if cleanup != nil {
		t.Fatal("ApplyCPULimit() returned cleanup for disabled limit")
	}
}
