//go:build linux

package security

import (
	"fmt"
	"syscall"
	"unsafe"

	"sandbox/sandbox/config"

	"golang.org/x/sys/unix"
)

const (
	SECCOMP_SET_MODE_FILTER   = 1
	SECCOMP_FILTER_FLAG_TSYNC = 1

	SECCOMP_RET_KILL_PROCESS = 0x80000000
	SECCOMP_RET_TRAP         = 0x00030000
	SECCOMP_RET_LOG          = 0x7ffc0000
	SECCOMP_RET_ALLOW        = 0x7fff0000
)

const (
	BPF_LD  = 0x00
	BPF_W   = 0x00
	BPF_ABS = 0x20
	BPF_JMP = 0x05
	BPF_RET = 0x06
	BPF_K   = 0x00
	BPF_JEQ = 0x10

	seccompDataArchOffset = 4
	seccompDataNrOffset   = 0
)

type sockFilter struct {
	code uint16
	jt   uint8
	jf   uint8
	k    uint32
}

type sockFprog struct {
	len    uint16
	filter *sockFilter
}

func actionToReturn(action config.SeccompAction) (uint32, error) {
	switch action {
	case config.ActionKill:
		return SECCOMP_RET_KILL_PROCESS, nil
	case config.ActionTrap:
		return SECCOMP_RET_TRAP, nil
	case config.ActionLog:
		return SECCOMP_RET_LOG, nil
	case config.ActionAllow:
		return SECCOMP_RET_ALLOW, nil
	default:
		return 0, fmt.Errorf("invalid seccomp action %q", action)
	}
}

func blockedSyscallNumbers(names []string) ([]uint32, error) {
	result := make([]uint32, 0, len(names))
	for _, name := range names {
		nr, ok := syscallNameToNumber[name]
		if !ok {
			return nil, fmt.Errorf("syscall %q is unavailable on this Linux architecture", name)
		}
		result = append(result, nr)
	}
	return result, nil
}

// ValidateSyscallNames is used by public configuration parsing so invalid
// names fail before any namespace or network resource is created.
func ValidateSyscallNames(names []string) error {
	_, err := blockedSyscallNumbers(names)
	return err
}

func ApplySeccompFilters() error {
	return ApplySeccompFiltersCustom(config.ActionKill, []string{"mount", "reboot", "ptrace", "swapon", "syslog"})
}

// ApplySeccompFiltersCustom installs an architecture-guarded filter. The
// architecture registry is split into build-tagged files so a cross-build
// cannot accidentally encode amd64 syscall numbers into an arm64 binary.
func ApplySeccompFiltersCustom(defaultAction config.SeccompAction, blockedSyscalls []string) error {
	if auditArchitecture == 0 {
		return fmt.Errorf("seccomp is unsupported on this Linux architecture")
	}
	returnAction, err := actionToReturn(defaultAction)
	if err != nil {
		return err
	}
	numbers, err := blockedSyscallNumbers(blockedSyscalls)
	if err != nil {
		return err
	}
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return fmt.Errorf("failed to set PR_SET_NO_NEW_PRIVS: %v", err)
	}

	instructions := []sockFilter{
		{BPF_LD | BPF_W | BPF_ABS, 0, 0, seccompDataArchOffset},
		{BPF_JMP | BPF_JEQ | BPF_K, 1, 0, auditArchitecture},
		{BPF_RET | BPF_K, 0, 0, SECCOMP_RET_KILL_PROCESS},
		{BPF_LD | BPF_W | BPF_ABS, 0, 0, seccompDataNrOffset},
	}
	for _, number := range numbers {
		instructions = append(instructions,
			sockFilter{BPF_JMP | BPF_JEQ | BPF_K, 0, 1, number},
			sockFilter{BPF_RET | BPF_K, 0, 0, returnAction},
		)
	}
	instructions = append(instructions, sockFilter{BPF_RET | BPF_K, 0, 0, SECCOMP_RET_ALLOW})

	prog := sockFprog{len: uint16(len(instructions)), filter: &instructions[0]}
	_, _, errno := syscall.Syscall6(
		uintptr(unix.SYS_SECCOMP), SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_TSYNC,
		uintptr(unsafe.Pointer(&prog)), 0, 0, 0,
	)
	if errno != 0 {
		return fmt.Errorf("kernel rejected seccomp filter loading: %v", errno)
	}
	return nil
}
