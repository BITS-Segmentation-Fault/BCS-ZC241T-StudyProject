//go:build linux

package fs

import (
	"fmt"
	"log"
	"os"
	"syscall"
)

// IsolateRootFS seals the child process inside a designated root filesystem directory tree
func IsolateRootFS(rootfsPath string) error {
	if rootfsPath == "" {
		return fmt.Errorf("value_error: isolated rootfs configuration path cannot be empty")
	}

	// PRE-FLIGHT VERIFICATION: Assert Jail Target Tree Validity inside VM
	info, err := os.Stat(rootfsPath)
	if os.IsNotExist(err) {
		return fmt.Errorf("pre-flight error: target rootfs path %q does not exist inside the environment. Please instantiate it first", rootfsPath)
	}
	if !info.IsDir() {
		return fmt.Errorf("pre-flight error: target rootfs path %q is an invalid format boundary (expected directory, found file)", rootfsPath)
	}
	log.Printf("[DEBUG] Pre-flight validation clear: Target jail system folder tree %q is valid.", rootfsPath)

	// 1. Mount Isolation Boundary
	err = syscall.Mount("", "/", "", syscall.MS_PRIVATE|syscall.MS_REC, "")
	if err != nil {
		return fmt.Errorf("failed to make root mount space private: %v", err)
	}

	// 2. Bind Mount Target
	err = syscall.Mount(rootfsPath, rootfsPath, "", syscall.MS_BIND|syscall.MS_REC, "")
	if err != nil {
		return fmt.Errorf("failed to bind-mount target rootfs path %q: %v", rootfsPath, err)
	}

	// 3. Proc Isolation
	procPath := rootfsPath + "/proc"
	if err := os.MkdirAll(procPath, 0755); err != nil {
		return fmt.Errorf("failed to create /proc directory inside sandbox tree: %v", err)
	}

	// - MS_NOSUID: Do not honor set-user-ID or set-group-ID bits inside the filesystem.
	// - MS_NODEV: Prevent character or block special devices from functioning.
	// - MS_NOEXEC: Prevent direct executable binaries traversal out of this space.
	procFlags := uintptr(syscall.MS_NOSUID | syscall.MS_NODEV | syscall.MS_NOEXEC)
	err = syscall.Mount("proc", procPath, "proc", procFlags, "")
	if err != nil {
		return fmt.Errorf("failed to mount hardened sandbox proc filesystem: %v", err)
	}

	// 4. Pivot Root Execution
	oldRootPath := rootfsPath + "/.old_host_root"
	if err := os.MkdirAll(oldRootPath, 0700); err != nil {
		return fmt.Errorf("failed to instantiate placeholder old_root mount path: %v", err)
	}

	// Pivot to new layout: new_root is rootfsPath, old_root is locked inside the temporary folder
	if err := syscall.PivotRoot(rootfsPath, oldRootPath); err != nil {
		return fmt.Errorf("syscall pivot_root boundary assertion failed: %v", err)
	}

	// Move working directory reference to the absolute new system root folder
	if err := syscall.Chdir("/"); err != nil {
		return fmt.Errorf("failed to settle working environment into new root: %v", err)
	}

	// 5. Unmount and Purge Old Host Path to leave the sandboxed application completely blind to any historical structural references.
	err = syscall.Unmount("/.old_host_root", syscall.MNT_DETACH)
	if err != nil {
		return fmt.Errorf("failed to detach and clear historical host root references: %v", err)
	}

	// Remove the temporary directory trace
	_ = os.Remove("/.old_host_root")

	return nil
}
