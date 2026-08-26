//go:build linux

package security

import (
	"testing"

	"sandbox/sandbox/config"
)

func TestBlockedSyscallNumbersRejectUnknownNames(t *testing.T) {
	if _, err := blockedSyscallNumbers([]string{"not-a-system-call"}); err == nil {
		t.Fatal("blockedSyscallNumbers() accepted an unknown syscall")
	}
}

func TestBlockedSyscallNumbersPreserveOrder(t *testing.T) {
	got, err := blockedSyscallNumbers([]string{"mount", "reboot"})
	if err != nil {
		t.Fatalf("blockedSyscallNumbers() error = %v", err)
	}
	if len(got) != 2 || got[0] != syscallNameToNumber["mount"] || got[1] != syscallNameToNumber["reboot"] {
		t.Fatalf("blockedSyscallNumbers() = %v, want mount/reboot numbers", got)
	}
}

func TestBuildFilterGuardsAuditArchitecture(t *testing.T) {
	instructions, err := buildFilter(config.ActionKill, []string{"mount"})
	if err != nil {
		t.Fatalf("buildFilter() error = %v", err)
	}
	if len(instructions) < 6 {
		t.Fatalf("buildFilter() returned too few instructions: %d", len(instructions))
	}
	if instructions[0].code != BPF_LD|BPF_W|BPF_ABS || instructions[0].k != seccompDataArchOffset {
		t.Fatalf("architecture load = %#v", instructions[0])
	}
	if instructions[1].code != BPF_JMP|BPF_JEQ|BPF_K || instructions[1].k != auditArchitecture || instructions[1].jt != 1 || instructions[1].jf != 0 {
		t.Fatalf("architecture guard = %#v", instructions[1])
	}
	if instructions[2].code != BPF_RET|BPF_K || instructions[2].k != SECCOMP_RET_KILL_PROCESS {
		t.Fatalf("architecture mismatch action = %#v", instructions[2])
	}
	if x32ABIBit != 0 {
		found := false
		for _, instruction := range instructions {
			if instruction.code == BPF_JMP|BPF_JSET|BPF_K && instruction.k == x32ABIBit {
				found = true
			}
		}
		if !found {
			t.Fatal("amd64 filter does not reject the x32 ABI bit")
		}
	}
}
