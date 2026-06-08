//go:build linux

package security

import (
	"fmt"
	"log"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Linux Kernel Seccomp Definitions
const (
	SECCOMP_SET_MODE_FILTER   = 1
	SECCOMP_FILTER_FLAG_TSYNC = 1

	// Seccomp Return Actions
	SECCOMP_RET_KILL_PROCESS = 0x80000000 // Tier 2: Hard kill process immediately
	SECCOMP_RET_TRAP         = 0x00030000 // Tier 2: Trigger SIGSYS signal to parent
	SECCOMP_RET_LOG          = 0x7ffc0000 // Tier 1: Allow but log to auditd
	SECCOMP_RET_ALLOW        = 0x7fff0000 // Standard operation: Allow call completely

	// BPF Opcode Instructions
	BPF_LD  = 0x00
	BPF_W   = 0x00
	BPF_ABS = 0x20
	BPF_JMP = 0x05
	BPF_RET = 0x06
	BPF_K   = 0x00
	BPF_JA  = 0x00
	BPF_JEQ = 0x10

	// Data offsets in seccomp_data struct passed by kernel
	seccomp_data_arch_offset = 4
	seccomp_data_nr_offset   = 0

	// Audit Token Architecture validation
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

// ApplySeccompFilters configures the two-tiered filtering mechanism inside child.go.
func ApplySeccompFilters() error {
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return fmt.Errorf("failed to set PR_SET_NO_NEW_PRIVS: %v", err)
	}

	instructions := []sockFilter{
		// 1. Load the CPU architecture token into the accumulator
		{BPF_LD | BPF_W | BPF_ABS, 0, 0, seccomp_data_arch_offset},
		// 2. If architecture is x86_64, skip the next instruction. If false, kill execution.
		{BPF_JMP | BPF_JEQ | BPF_K, 1, 0, AUDIT_ARCH_X86_64},
		{BPF_RET | BPF_K, 0, 0, SECCOMP_RET_KILL_PROCESS},

		// 3. Load the requested system call number into the accumulator
		{BPF_LD | BPF_W | BPF_ABS, 0, 0, seccomp_data_nr_offset},

		// TIER 2: CRITICAL WARNINGS (Block & Trap to Parent via SIGSYS)
		// If syscall == sys_reboot (167), trap execution
		{BPF_JMP | BPF_JEQ | BPF_K, 0, 1, 167},
		{BPF_RET | BPF_K, 0, 0, SECCOMP_RET_TRAP},

		// If syscall == sys_mount (165), trap execution
		{BPF_JMP | BPF_JEQ | BPF_K, 0, 1, 165},
		{BPF_RET | BPF_K, 0, 0, SECCOMP_RET_TRAP},

		// If syscall == sys_ptrace (101), trap execution
		{BPF_JMP | BPF_JEQ | BPF_K, 0, 1, 101},
		{BPF_RET | BPF_K, 0, 0, SECCOMP_RET_TRAP},

		// TIER 1: WARNINGS
		{BPF_JMP | BPF_JEQ | BPF_K, 0, 1, 50},
		{BPF_RET | BPF_K, 0, 0, SECCOMP_RET_LOG},

		{BPF_JMP | BPF_JEQ | BPF_K, 0, 1, 43},
		{BPF_RET | BPF_K, 0, 0, SECCOMP_RET_LOG},

		// DEFAULT FALLBACK PASS RULES
		{BPF_RET | BPF_K, 0, 0, SECCOMP_RET_ALLOW},
	}

	prog := sockFprog{
		len:    uint16(len(instructions)),
		filter: &instructions[0],
	}

	log.Printf("[DEBUG] Attempting to arm kernel Seccomp engine. Total instruction blocks: %d", prog.len)

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
