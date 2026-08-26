//go:build linux

package resources

import (
	"fmt"
	"syscall"
)

const mbToBytes = 1024 * 1024

// ApplyFileSizeLimit applies a fixed per-file RLIMIT_FSIZE ceiling. It does
// not account for aggregate storage usage.
func ApplyFileSizeLimit(limitMB int) error {
	if limitMB < 0 {
		return fmt.Errorf("file-size limit must not be negative")
	}
	if limitMB == 0 {
		return nil
	}
	if uint64(limitMB) > ^uint64(0)/mbToBytes {
		return fmt.Errorf("file-size limit overflows the kernel limit")
	}
	bytes := uint64(limitMB) * mbToBytes
	limit := syscall.Rlimit{Cur: bytes, Max: bytes}
	if err := syscall.Setrlimit(syscall.RLIMIT_FSIZE, &limit); err != nil {
		return fmt.Errorf("kernel rejected file-size limit: %w", err)
	}
	return nil
}
