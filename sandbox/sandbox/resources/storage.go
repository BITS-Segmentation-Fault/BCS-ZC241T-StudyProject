//go:build linux

package resources

import (
	"fmt"
	"log"
	"syscall"
	"unsafe"

	"sandbox/sandbox/config"
)

const mbToBytes = 1024 * 1024

// Bind the starting capacity ceiling to the child process.
func ApplyInitialStorageLimit(cfg config.StorageConfig) error {
	initialBytes := uint64(cfg.InitialLimitMB) * mbToBytes
	maxBytes := uint64(cfg.AbsoluteMaximumMB) * mbToBytes

	rLimit := syscall.Rlimit{
		Cur: initialBytes, // Current limit: Triggers SIGXFSZ if breached
		Max: maxBytes,     // Absolute kernel limit ceiling
	}

	if err := syscall.Setrlimit(syscall.RLIMIT_FSIZE, &rLimit); err != nil {
		return fmt.Errorf("Kernel rejected storage resource limits initialization: %v", err)
	}
	return nil
}

// Check the policy matrix when a file size threshold is reached.
func EvaluateStorageExpansion(pid int, cfg config.StorageConfig, currentExpansionCount int) (bool, int) {
	currentLimitMB := cfg.InitialLimitMB + (currentExpansionCount * cfg.IncrementStepMB)
	nextLimitMB := currentLimitMB + cfg.IncrementStepMB

	if currentLimitMB >= cfg.AbsoluteMaximumMB {
		log.Printf("[🚨 CRITICAL STORAGE ALERT] Sandbox PID %d hit hard stop ceiling of %d MB. Denying allocation.", pid, cfg.AbsoluteMaximumMB)
		return false, currentExpansionCount
	}

	switch cfg.ExpansionPolicy {
	case "none":
		log.Printf("[🚨 CRITICAL STORAGE ALERT] Sandbox PID %d crossed storage threshold. Policy set to 'none'. Hard stopping.", pid)
		return false, currentExpansionCount

	case "automatic":
		if nextLimitMB > cfg.AbsoluteMaximumMB {
			nextLimitMB = cfg.AbsoluteMaximumMB
		}

		newLimitBytes := uint64(nextLimitMB) * mbToBytes
		maxBytes := uint64(cfg.AbsoluteMaximumMB) * mbToBytes

		newRLimit := syscall.Rlimit{
			Cur: newLimitBytes,
			Max: maxBytes,
		}

		// Use Linux Prlimit64 via raw syscall to rewrite the limits of the live running child process remotely
		_, _, errno := syscall.Syscall6(
			syscall.SYS_PRLIMIT64,
			uintptr(pid),
			uintptr(syscall.RLIMIT_FSIZE),
			uintptr(unsafe.Pointer(&newRLimit)),
			0, 0, 0,
		)

		if errno != 0 {
			log.Printf("[ERROR] Failed to dynamically shift child process storage limit via prlimit64: %v", errno)
			return false, currentExpansionCount
		}

		log.Printf("[TIER 1 WARNING] Sandbox PID %d breached allocation threshold. Automatically expanded storage limit to %d MB.", pid, nextLimitMB)
		return true, currentExpansionCount + 1

	case "manual":
		log.Printf("[TIER 1 WARNING] Sandbox PID %d requires manual interaction approval to allocate more disk space.", pid)
		return false, currentExpansionCount
	}

	return false, currentExpansionCount
}
