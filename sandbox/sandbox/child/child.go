//go:build linux

package child

import (
	"fmt"
	"syscall"

	"sandbox/demo/config"
	"sandbox/demo/fs"
	"sandbox/demo/security"

	"golang.org/x/sys/unix"
)

func childLog(msg string) {
	_, _ = syscall.Write(1, []byte(fmt.Sprintf("[CHILD DEBUG] %s\n", msg)))
}

func Child(cfg config.Config, p2cRFd uintptr, c2pWFd uintptr, hostUID int, hostGID int) int {
	childLog("Child process entered execution layer.")

	childLog("Removing inherited host file descriptors...")
	for fd := 3; fd < 1024; fd++ {
		if uintptr(fd) == p2cRFd || uintptr(fd) == c2pWFd {
			continue
		}
		_ = syscall.Close(fd)
	}

	// ISOLATION: Detach mount and hostname namespaces from host
	childLog("Requesting remaining kernel namespace isolation (CLONE_NEWNS | CLONE_NEWUTS)...")

	err := syscall.Unshare(syscall.CLONE_NEWNS | syscall.CLONE_NEWUTS)
	if err != nil {
		childLog(fmt.Sprintf("🚨 UNSHARE FAILURE: %v", err))
		return 1
	}
	childLog("Namespaces successfully partitioned from host.")

	// FILESYSTEM JAIL: Isolate rootfs tree boundaries
	childLog("Triggering pivot_root jail isolation layer...")
	rootfsTarget := "/var/lib/sandbox/rootfs"
	if err := fs.IsolateRootFS(rootfsTarget); err != nil {
		childLog(fmt.Sprintf("🚨 CRITICAL JAIL FAILURE: %v", err))
		return 1
	}
	childLog("Filesystem isolation asserted. Host system tree completely blinded.")

	// SECURITY POLICIES: Load Seccomp Restrictions
	childLog("Arming Seccomp kernel filter engine rules...")
	if err := security.ApplySeccompFilters(); err != nil {
		childLog(fmt.Sprintf("🚨 SECCOMP FAILURE: %v", err))
		return 1
	}
	childLog("Seccomp kernel filters successfully armed.")

	// RUNTIME EXECUTION: Hand off control to payload binary
	childLog("Handing off thread execution track to internal target binary path (/bin/payload)...")

	binaryPath := "/bin/payload"
	args := []string{binaryPath}
	env := []string{"PATH=/bin:/usr/bin", "TERM=xterm"}

	execErr := unix.Exec(binaryPath, args, env)
	if execErr != nil {
		childLog(fmt.Sprintf("🚨 KERNEL EXECVE CRITICAL FAILURE: %v", execErr))
		return 1
	}

	return 0
}
