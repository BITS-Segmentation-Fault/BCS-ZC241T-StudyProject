//go:build linux

package fs

import (
	"fmt"
	"log"
	"os"
	"syscall"

	"sandbox/demo/config"
)

// Seal the child process inside a designated root filesystem directory tree,
func IsolateRootFS(rootfsPath string, bindMounts []config.BindMount) error {
	if rootfsPath == "" {
		return fmt.Errorf("value_error: isolated rootfs configuration path cannot be empty")
	}

	info, err := os.Stat(rootfsPath)
	if os.IsNotExist(err) {
		return fmt.Errorf("pre-flight error: target rootfs path %q does not exist", rootfsPath)
	}
	if !info.IsDir() {
		return fmt.Errorf("pre-flight error: target rootfs path %q is not a directory", rootfsPath)
	}
	log.Printf("[DEBUG] Pre-flight validation clear: Target jail system tree %q is valid.", rootfsPath)

	// Mount Isolation Boundary
	err = syscall.Mount("", "/", "", syscall.MS_PRIVATE|syscall.MS_REC, "")
	if err != nil {
		return fmt.Errorf("failed to make root mount space private: %v", err)
	}

	// Bind Mount Target
	err = syscall.Mount(rootfsPath, rootfsPath, "", syscall.MS_BIND|syscall.MS_REC, "")
	if err != nil {
		return fmt.Errorf("failed to bind-mount target rootfs path %q: %v", rootfsPath, err)
	}

	// Apply host-to-container bind mounts before pivot_root
	for _, bm := range bindMounts {
		targetPath := rootfsPath + bm.ContainerPath
		if err := os.MkdirAll(targetPath, 0755); err != nil {
			return fmt.Errorf("failed to create bind mount target %q: %v", targetPath, err)
		}
		mountFlags := uintptr(syscall.MS_BIND | syscall.MS_REC)
		if err := syscall.Mount(bm.HostPath, targetPath, "", mountFlags, ""); err != nil {
			return fmt.Errorf("failed to bind mount %q to %q: %v", bm.HostPath, targetPath, err)
		}
		if bm.ReadOnly {
			readOnlyFlags := uintptr(syscall.MS_BIND | syscall.MS_REMOUNT | syscall.MS_RDONLY | syscall.MS_REC)
			if err := syscall.Mount(bm.HostPath, targetPath, "", readOnlyFlags, ""); err != nil {
				return fmt.Errorf("failed to remount bind mount %q read-only: %v", targetPath, err)
			}
		}
		log.Printf("[DEBUG] Bind mount applied: %s -> %s (ro=%v)", bm.HostPath, targetPath, bm.ReadOnly)
	}

	// Proc Isolation
	procPath := rootfsPath + "/proc"
	if err := os.MkdirAll(procPath, 0755); err != nil {
		return fmt.Errorf("failed to create /proc directory inside sandbox tree: %v", err)
	}

	procFlags := uintptr(syscall.MS_NOSUID | syscall.MS_NODEV | syscall.MS_NOEXEC)
	err = syscall.Mount("proc", procPath, "proc", procFlags, "")
	if err != nil {
		return fmt.Errorf("failed to mount hardened sandbox proc filesystem: %v", err)
	}

	// Pivot Root Execution
	oldRootPath := rootfsPath + "/.old_host_root"
	if err := os.MkdirAll(oldRootPath, 0700); err != nil {
		return fmt.Errorf("failed to create placeholder old_root mount path: %v", err)
	}

	if err := syscall.PivotRoot(rootfsPath, oldRootPath); err != nil {
		return fmt.Errorf("syscall pivot_root boundary assertion failed: %v", err)
	}

	if err := syscall.Chdir("/"); err != nil {
		return fmt.Errorf("failed to settle working environment into new root: %v", err)
	}

	// Unmount and purge old host root
	err = syscall.Unmount("/.old_host_root", syscall.MNT_DETACH)
	if err != nil {
		return fmt.Errorf("failed to detach and clear historical host root references: %v", err)
	}

	_ = os.Remove("/.old_host_root")

	return nil
}
