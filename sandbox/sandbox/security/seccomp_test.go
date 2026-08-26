//go:build linux

package security

import (
	"testing"

	"sandbox/sandbox/config"

	"golang.org/x/sys/unix"
)

func TestBlockedSyscallNumbersRejectUnknownNames(t *testing.T) {
	if _, err := blockedSyscallNumbers([]string{"not-a-system-call"}); err == nil {
		t.Fatal("blockedSyscallNumbers() accepted an unknown syscall")
	}
}

func TestBlockedSyscallNumbersRejectDuplicates(t *testing.T) {
	if _, err := blockedSyscallNumbers([]string{"mount", "mount"}); err == nil {
		t.Fatal("blockedSyscallNumbers() accepted a duplicate syscall")
	}
}

func TestActions(t *testing.T) {
	tests := []struct {
		action config.SeccompAction
		valid  bool
	}{
		{config.ActionKill, true},
		{config.ActionTrap, true},
		{config.SeccompAction("allow"), false},
	}
	for _, test := range tests {
		_, err := actionToReturn(test.action)
		if (err == nil) != test.valid {
			t.Errorf("actionToReturn(%q) error = %v, valid = %v", test.action, err, test.valid)
		}
	}
}

func TestBuildFilterGuardsAuditArchitecture(t *testing.T) {
	instructions, err := buildFilter(config.ActionKill, []string{"mount"})
	if auditArchitecture == 0 {
		if err == nil {
			t.Fatal("buildFilter() accepted an unsupported architecture")
		}
		return
	}
	if err != nil {
		t.Fatalf("buildFilter() error = %v", err)
	}
	if len(instructions) < 6 {
		t.Fatalf("buildFilter() returned too few instructions: %d", len(instructions))
	}
	if instructions[0].Code != unix.BPF_LD|unix.BPF_W|unix.BPF_ABS || instructions[0].K != seccompDataArchOffset {
		t.Fatalf("architecture load = %#v", instructions[0])
	}
	if instructions[1].Code != unix.BPF_JMP|unix.BPF_JEQ|unix.BPF_K || instructions[1].K != auditArchitecture || instructions[1].Jt != 1 || instructions[1].Jf != 0 {
		t.Fatalf("architecture guard = %#v", instructions[1])
	}
	if instructions[2].Code != unix.BPF_RET|unix.BPF_K || instructions[2].K != unix.SECCOMP_RET_KILL_PROCESS {
		t.Fatalf("architecture mismatch action = %#v", instructions[2])
	}
	if x32ABIBit != 0 {
		found := false
		for _, instruction := range instructions {
			if instruction.Code == unix.BPF_JMP|unix.BPF_JSET|unix.BPF_K && instruction.K == x32ABIBit {
				found = true
			}
		}
		if !found {
			t.Fatal("amd64 filter does not reject the x32 ABI bit")
		}
	}
}
