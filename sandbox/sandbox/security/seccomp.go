//go:build linux

package security

import (
	"fmt"
	"unsafe"

	"sandbox/sandbox/config"

	"golang.org/x/sys/unix"
)

const (
	seccompDataArchOffset = 4
	seccompDataNrOffset   = 0
)

func actionToReturn(action config.SeccompAction) (uint32, error) {
	switch action {
	case config.ActionKill:
		return unix.SECCOMP_RET_KILL_PROCESS, nil
	case config.ActionTrap:
		return unix.SECCOMP_RET_TRAP, nil
	default:
		return 0, fmt.Errorf("invalid seccomp action %q", action)
	}
}

func blockedSyscallNumbers(names []string) ([]uint32, error) {
	if err := validateArchitecture(); err != nil {
		return nil, err
	}
	result := make([]uint32, 0, len(names))
	seen := make(map[string]struct{}, len(names))
	for _, name := range names {
		if _, ok := seen[name]; ok {
			return nil, fmt.Errorf("syscall %q is listed more than once", name)
		}
		seen[name] = struct{}{}
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

func validateArchitecture() error {
	if auditArchitecture == 0 {
		return fmt.Errorf("seccomp is unsupported on this Linux architecture")
	}
	return nil
}

// ApplySeccompFilter installs an architecture-guarded filter. The
// architecture registry is split into build-tagged files so a cross-build
// cannot accidentally encode amd64 syscall numbers into an arm64 binary.
func ApplySeccompFilter(blockedSyscallAction config.SeccompAction, blockedSyscalls []string) error {
	instructions, err := buildFilter(blockedSyscallAction, blockedSyscalls)
	if err != nil {
		return err
	}
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return fmt.Errorf("failed to set PR_SET_NO_NEW_PRIVS: %w", err)
	}

	prog := unix.SockFprog{Len: uint16(len(instructions)), Filter: &instructions[0]}
	result, _, errno := unix.Syscall6(
		unix.SYS_SECCOMP, unix.SECCOMP_SET_MODE_FILTER, unix.SECCOMP_FILTER_FLAG_TSYNC,
		uintptr(unsafe.Pointer(&prog)), 0, 0, 0,
	)
	if errno != 0 {
		return fmt.Errorf("kernel rejected seccomp filter loading: %w", errno)
	}
	if result != 0 {
		return fmt.Errorf("kernel could not synchronize seccomp filter to thread %d", result)
	}
	return nil
}

func buildFilter(blockedSyscallAction config.SeccompAction, blockedSyscalls []string) ([]unix.SockFilter, error) {
	numbers, err := blockedSyscallNumbers(blockedSyscalls)
	if err != nil {
		return nil, err
	}
	returnAction, err := actionToReturn(blockedSyscallAction)
	if err != nil {
		return nil, err
	}

	instructions := []unix.SockFilter{
		{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: seccompDataArchOffset},
		{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jt: 1, K: auditArchitecture},
		{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_KILL_PROCESS},
		{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: seccompDataNrOffset},
	}
	if x32ABIBit != 0 {
		instructions = append(instructions,
			unix.SockFilter{Code: unix.BPF_JMP | unix.BPF_JSET | unix.BPF_K, Jt: 0, Jf: 1, K: x32ABIBit},
			unix.SockFilter{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_KILL_PROCESS},
		)
	}
	for _, number := range numbers {
		instructions = append(instructions,
			unix.SockFilter{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jt: 0, Jf: 1, K: number},
			unix.SockFilter{Code: unix.BPF_RET | unix.BPF_K, K: returnAction},
		)
	}
	instructions = append(instructions, unix.SockFilter{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_ALLOW})
	if len(instructions) == 0 || len(instructions) > unix.BPF_MAXINSNS {
		return nil, fmt.Errorf("seccomp filter has invalid instruction count %d", len(instructions))
	}
	return instructions, nil
}
