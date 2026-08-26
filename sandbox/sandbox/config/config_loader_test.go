package config

import (
	"strings"
	"testing"
)

func TestLoadConfigDefaultsAndOverride(t *testing.T) {
	c, err := LoadConfigFromReader(strings.NewReader("command: [/bin/echo, hello]\n"))
	if err != nil {
		t.Fatal(err)
	}
	if c.BlockedSyscallAction != ActionKill || c.FileSizeLimitMB != 100 || c.CPULimitPercent != 0 || c.MemoryLimitGB != 1 || c.MaxProcesses != 100 || c.RootFSSource != "/var/lib/sandbox/rootfs" || c.WorkingDir != "/" {
		t.Fatalf("defaults lost: %+v", c)
	}
	c, err = LoadConfigFromReader(strings.NewReader("command: [/bin/echo]\nblocked_syscall_action: trap\nfile_size_limit_mb: 4\n"))
	if err != nil || c.BlockedSyscallAction != ActionTrap || c.FileSizeLimitMB != 4 {
		t.Fatalf("override failed: %v %+v", err, c)
	}
}

func TestLoadConfigRejectsBoundaries(t *testing.T) {
	tests := []string{
		"command: [/bin/echo]\nunknown: true\n",
		"command: [/bin/echo]\n---\ncommand: [/bin/false]\n",
		"command: [/bin/echo]\nfile_size_limit_mb: -1\n",
	}
	for _, input := range tests {
		if _, err := LoadConfigFromReader(strings.NewReader(input)); err == nil {
			t.Errorf("accepted invalid YAML %q", input)
		}
	}
	oversized := strings.Repeat("x", maxConfigBytes+1)
	if _, err := LoadConfigFromReader(strings.NewReader(oversized)); err == nil {
		t.Error("accepted oversized configuration")
	}
}
