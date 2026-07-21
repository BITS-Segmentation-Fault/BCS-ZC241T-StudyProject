//go:build linux

package security

import (
	"fmt"
	"log"
	"syscall"
	"unsafe"

	"sandbox/sandbox/config"

	"golang.org/x/sys/unix"
)

// Seccomp constants
const (
	SECCOMP_SET_MODE_FILTER   = 1
	SECCOMP_FILTER_FLAG_TSYNC = 1

	SECCOMP_RET_KILL_PROCESS = 0x80000000
	SECCOMP_RET_TRAP         = 0x00030000
	SECCOMP_RET_LOG          = 0x7ffc0000
	SECCOMP_RET_ALLOW        = 0x7fff0000
)

// BPF opcodes
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

	AUDIT_ARCH_X86_64 = 0xc000003e
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

// Map human-readable syscall names to platform-specific numbers.
var syscallNameToNumber = map[string]uint32{
	"reboot":            uint32(unix.SYS_REBOOT),
	"mount":             uint32(unix.SYS_MOUNT),
	"ptrace":            uint32(unix.SYS_PTRACE),
	"swapon":            uint32(unix.SYS_SWAPON),
	"syslog":            uint32(unix.SYS_SYSLOG),
	"init_module":       uint32(unix.SYS_INIT_MODULE),
	"finit_module":      uint32(unix.SYS_FINIT_MODULE),
	"delete_module":     uint32(unix.SYS_DELETE_MODULE),
	"iopl":              uint32(unix.SYS_IOPL),
	"ioperm":            uint32(unix.SYS_IOPERM),
	"kcmp":              uint32(unix.SYS_KCMP),
	"process_vm_readv":  uint32(unix.SYS_PROCESS_VM_READV),
	"process_vm_writev": uint32(unix.SYS_PROCESS_VM_WRITEV),
	"nfsservctl":        uint32(unix.SYS_NFSSERVCTL),
	"create_module":     uint32(unix.SYS_CREATE_MODULE),
}

// Map SeccompAction to its SECCOMP_RET_* constant.
func actionToReturn(action config.SeccompAction) uint32 {
	switch action {
	case config.ActionKill:
		return SECCOMP_RET_KILL_PROCESS
	case config.ActionTrap:
		return SECCOMP_RET_TRAP
	case config.ActionLog:
		return SECCOMP_RET_LOG
	case config.ActionAllow:
		return SECCOMP_RET_ALLOW
	default:
		return SECCOMP_RET_KILL_PROCESS
	}
}

// Backwards-compatible shim that uses default secure settings.
func ApplySeccompFilters() error {
	return ApplySeccompFiltersCustom(config.ActionKill, []string{"mount", "reboot", "ptrace", "swapon", "syslog"})
}

// Install a BPF seccomp filter that blocks the given syscalls and apply the specified default action when a blocked call is detected.
func ApplySeccompFiltersCustom(defaultAction config.SeccompAction, blockedSyscalls []string) error {
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return fmt.Errorf("failed to set PR_SET_NO_NEW_PRIVS: %v", err)
	}

	returnAction := actionToReturn(defaultAction)

	// Build instruction list
	var instructions []sockFilter

	// Load architecture
	instructions = append(instructions, sockFilter{BPF_LD | BPF_W | BPF_ABS, 0, 0, seccompDataArchOffset})
	// 1: Check architecture == x86_64; if not, kill
	instructions = append(instructions, sockFilter{BPF_JMP | BPF_JEQ | BPF_K, 1, 0, AUDIT_ARCH_X86_64})
	instructions = append(instructions, sockFilter{BPF_RET | BPF_K, 0, 0, SECCOMP_RET_KILL_PROCESS})

	// Load syscall number
	instructions = append(instructions, sockFilter{BPF_LD | BPF_W | BPF_ABS, 0, 0, seccompDataNrOffset})

	// For each blocked syscall, emit: BPF_JEQ nr, 0, 1  /  RET action
	for _, name := range blockedSyscalls {
		nr, ok := syscallNameToNumber[name]
		if !ok {
			log.Printf("[WARNING] Unknown syscall name %q — skipping seccomp rule", name)
			continue
		}
		instructions = append(instructions, sockFilter{BPF_JMP | BPF_JEQ | BPF_K, 0, 1, uint32(nr)})
		instructions = append(instructions, sockFilter{BPF_RET | BPF_K, 0, 0, returnAction})
	}

	// Fall through: allow
	instructions = append(instructions, sockFilter{BPF_RET | BPF_K, 0, 0, SECCOMP_RET_ALLOW})

	prog := sockFprog{
		len:    uint16(len(instructions)),
		filter: &instructions[0],
	}

	log.Printf("[DEBUG] Arming seccomp filter. %d blocked syscalls, default action=0x%08x, total BPF blocks=%d",
		len(blockedSyscalls), returnAction, prog.len)

	_, _, errno := syscall.Syscall6(
		uintptr(unix.SYS_SECCOMP),
		SECCOMP_SET_MODE_FILTER,
		SECCOMP_FILTER_FLAG_TSYNC,
		uintptr(unsafe.Pointer(&prog)),
		0, 0, 0,
	)

	if errno != 0 {
		return fmt.Errorf("kernel rejected seccomp filter loading: %v", errno)
	}

	return nil
}
