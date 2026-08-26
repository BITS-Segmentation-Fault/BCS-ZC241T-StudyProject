//go:build linux

package resources

import (
	"fmt"
	"math"

	"golang.org/x/sys/unix"
)

const mbToBytes = 1024 * 1024

// ApplyFileSizeLimit applies a fixed per-file RLIMIT_FSIZE ceiling without
// weakening a stricter inherited limit. Zero leaves the inherited limit alone.
func ApplyFileSizeLimit(limitMB int) error {
	if limitMB < 0 {
		return fmt.Errorf("file-size limit must not be negative")
	}
	if limitMB == 0 {
		return nil
	}
	if uint64(limitMB) > math.MaxUint64/mbToBytes {
		return fmt.Errorf("file-size limit overflows the kernel limit")
	}
	bytes := uint64(limitMB) * mbToBytes
	var inherited unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_FSIZE, &inherited); err != nil {
		return fmt.Errorf("cannot read inherited file-size limit: %w", err)
	}
	ceiling := bytes
	if inherited.Cur != unix.RLIM_INFINITY && inherited.Cur < ceiling {
		ceiling = inherited.Cur
	}
	if inherited.Max != unix.RLIM_INFINITY && inherited.Max < ceiling {
		ceiling = inherited.Max
	}
	limit := unix.Rlimit{Cur: ceiling, Max: ceiling}
	if err := unix.Setrlimit(unix.RLIMIT_FSIZE, &limit); err != nil {
		return fmt.Errorf("kernel rejected file-size limit: %w", err)
	}
	return nil
}
