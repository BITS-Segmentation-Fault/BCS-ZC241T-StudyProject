//go:build linux

package security

import (
	"runtime"
	"testing"
)

func TestAuditArchitectureForSupportedLinuxTargets(t *testing.T) {
	want := map[string]uint32{"amd64": 0xc000003e, "arm64": 0xc00000b7}[runtime.GOARCH]
	if auditArchitecture != want {
		t.Fatalf("audit architecture = %#x, want %#x", auditArchitecture, want)
	}
}

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
