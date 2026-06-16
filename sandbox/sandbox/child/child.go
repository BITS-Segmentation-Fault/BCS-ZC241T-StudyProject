//go:build linux

package child

import (
	"fmt"
	"strings"
	"syscall"

	"sandbox/demo/config"
	"sandbox/demo/fs"
	"sandbox/demo/security"

	"golang.org/x/sys/unix"
)

// capabilityNameToValue maps human-readable capability names to Linux constants.
var capabilityNameToValue = map[string]uintptr{
	"CAP_SYS_ADMIN":        unix.CAP_SYS_ADMIN,
	"CAP_NET_ADMIN":        unix.CAP_NET_ADMIN,
	"CAP_SYS_PTRACE":       unix.CAP_SYS_PTRACE,
	"CAP_SYS_MODULE":       unix.CAP_SYS_MODULE,
	"CAP_SYS_RAWIO":        unix.CAP_SYS_RAWIO,
	"CAP_SYS_BOOT":         unix.CAP_SYS_BOOT,
	"CAP_SYS_TIME":         unix.CAP_SYS_TIME,
	"CAP_SYSLOG":           unix.CAP_SYSLOG,
	"CAP_NET_RAW":          unix.CAP_NET_RAW,
	"CAP_NET_BIND_SERVICE": unix.CAP_NET_BIND_SERVICE,
	"CAP_DAC_OVERRIDE":     unix.CAP_DAC_OVERRIDE,
	"CAP_CHOWN":            unix.CAP_CHOWN,
	"CAP_FOWNER":           unix.CAP_FOWNER,
	"CAP_KILL":             unix.CAP_KILL,
	"CAP_SETUID":           unix.CAP_SETUID,
	"CAP_SETGID":           unix.CAP_SETGID,
	"CAP_SETPCAP":          unix.CAP_SETPCAP,
	"CAP_MKNOD":            unix.CAP_MKNOD,
	"CAP_AUDIT_WRITE":      unix.CAP_AUDIT_WRITE,
	"CAP_AUDIT_CONTROL":    unix.CAP_AUDIT_CONTROL,
	"CAP_MAC_OVERRIDE":     unix.CAP_MAC_OVERRIDE,
	"CAP_MAC_ADMIN":        unix.CAP_MAC_ADMIN,
	"CAP_SYS_NICE":         unix.CAP_SYS_NICE,
	"CAP_SYS_RESOURCE":     unix.CAP_SYS_RESOURCE,
	"CAP_SYS_TTY_CONFIG":   unix.CAP_SYS_TTY_CONFIG,
	"CAP_IPC_LOCK":         unix.CAP_IPC_LOCK,
	"CAP_IPC_OWNER":        unix.CAP_IPC_OWNER,
	"CAP_NET_BROADCAST":    unix.CAP_NET_BROADCAST,
	"CAP_WAKE_ALARM":       unix.CAP_WAKE_ALARM,
	"CAP_BLOCK_SUSPEND":    unix.CAP_BLOCK_SUSPEND,
}

const mbToBytes = 1024 * 1024
const gbToBytes = 1024 * 1024 * 1024

func childLog(msg string) {
	_, _ = syscall.Write(1, []byte(fmt.Sprintf("[CHILD DEBUG] %s\n", msg)))
}

func Child(cfg config.Config, p2cRFd uintptr, c2pWFd uintptr, hostUID int, hostGID int) int {
	childLog("Child process entered execution layer.")

	// Close inherited host file descriptors
	childLog("Removing inherited host file descriptors...")
	for fd := 3; fd < 1024; fd++ {
		if uintptr(fd) == p2cRFd || uintptr(fd) == c2pWFd {
			continue
		}
		_ = syscall.Close(fd)
	}

	// Namespace isolation
	childLog("Requesting remaining kernel namespace isolation (CLONE_NEWNS | CLONE_NEWUTS)...")
	err := syscall.Unshare(syscall.CLONE_NEWNS | syscall.CLONE_NEWUTS)
	if err != nil {
		childLog(fmt.Sprintf("UNSHARE FAILURE: %v", err))
		return 1
	}

	// Drop capabilities before pivot_root
	childLog("Dropping kernel capabilities...")
	for _, capName := range cfg.DropCapabilities {
		capVal, ok := capabilityNameToValue[capName]
		if !ok {
			childLog(fmt.Sprintf("WARNING: unknown capability %q — skipping", capName))
			continue
		}
		if err := unix.Prctl(unix.PR_CAPBSET_DROP, capVal, 0, 0, 0); err != nil {
			childLog(fmt.Sprintf("WARNING: failed to drop capability %s: %v", capName, err))
		}
	}

	// Apply bind mounts and pivot_root
	rootfsTarget := cfg.RootFSSource
	if rootfsTarget == "" {
		rootfsTarget = "/var/lib/sandbox/rootfs"
	}
	childLog(fmt.Sprintf("Triggering pivot_root jail isolation to %q...", rootfsTarget))
	if err := fs.IsolateRootFS(rootfsTarget, cfg.BindMounts); err != nil {
		childLog(fmt.Sprintf("CRITICAL JAIL FAILURE: %v", err))
		return 1
	}

	// Remount / as read-only if configured
	if cfg.ReadOnlyRoot {
		childLog("Setting root filesystem to read-only...")
		if err := syscall.Mount("", "/", "", syscall.MS_REMOUNT|syscall.MS_RDONLY|syscall.MS_BIND, ""); err != nil {
			childLog(fmt.Sprintf("WARNING: failed to remount root read-only: %v", err))
		}
	}

	// Write DNS servers to /etc/resolv.conf
	if len(cfg.DNSServers) > 0 {
		childLog("Writing DNS servers to /etc/resolv.conf...")
		var lines []string
		for _, dns := range cfg.DNSServers {
			lines = append(lines, "nameserver "+dns)
		}
		content := strings.Join(lines, "\n") + "\n"
		if err := fs.WriteText("/etc/resolv.conf", content); err != nil {
			childLog(fmt.Sprintf("WARNING: failed to write /etc/resolv.conf: %v", err))
		}
	}

	// Apply resource limits
	childLog("Applying resource limits...")

	// CPU limit
	if cfg.CPULimitPercent > 0 {
		cpuSecs := uint64(cfg.CPULimitPercent) * 3600 / 100
		rlim := syscall.Rlimit{Cur: cpuSecs, Max: cpuSecs}
		if err := syscall.Setrlimit(syscall.RLIMIT_CPU, &rlim); err != nil {
			childLog(fmt.Sprintf("WARNING: failed to set RLIMIT_CPU: %v", err))
		}
	}

	// Memory limit
	if cfg.MemoryLimitGB > 0 {
		memBytes := uint64(cfg.MemoryLimitGB) * gbToBytes
		rlim := syscall.Rlimit{Cur: memBytes, Max: memBytes}
		if err := syscall.Setrlimit(syscall.RLIMIT_AS, &rlim); err != nil {
			childLog(fmt.Sprintf("WARNING: failed to set RLIMIT_AS: %v", err))
		}
	}

	// Processes limit
	if cfg.MaxProcesses > 0 {
		rlim := syscall.Rlimit{Cur: uint64(cfg.MaxProcesses), Max: uint64(cfg.MaxProcesses)}
		if err := syscall.Setrlimit(syscall.RLIMIT_NPROC, &rlim); err != nil {
			childLog(fmt.Sprintf("WARNING: failed to set RLIMIT_NPROC: %v", err))
		}
	}

	// Storage limits
	storageCfg := cfg.Storage
	initialBytes := uint64(storageCfg.InitialLimitMB) * mbToBytes
	maxBytes := uint64(storageCfg.AbsoluteMaximumMB) * mbToBytes
	rlimitFsize := syscall.Rlimit{Cur: initialBytes, Max: maxBytes}
	if err := syscall.Setrlimit(syscall.RLIMIT_FSIZE, &rlimitFsize); err != nil {
		childLog(fmt.Sprintf("WARNING: failed to set RLIMIT_FSIZE: %v", err))
	}

	// Seccomp
	childLog("Arming seccomp kernel filter engine...")
	if err := security.ApplySeccompFiltersCustom(cfg.SeccompDefaultAction, cfg.BlockedSyscalls); err != nil {
		childLog(fmt.Sprintf("SECCOMP FAILURE: %v", err))
		return 1
	}

	// Working directory
	if cfg.WorkingDir != "" && cfg.WorkingDir != "/" {
		childLog(fmt.Sprintf("Changing working directory to %q...", cfg.WorkingDir))
		if err := syscall.Chdir(cfg.WorkingDir); err != nil {
			childLog(fmt.Sprintf("WARNING: failed to chdir to %q: %v", cfg.WorkingDir, err))
		}
	}

	// Determine binary path and args
	binaryPath := cfg.BinaryPath
	var execArgs []string
	if binaryPath == "" && len(cfg.Command) > 0 {
		binaryPath = cfg.Command[0]
		execArgs = cfg.Command
	} else if binaryPath != "" {
		execArgs = append([]string{binaryPath}, cfg.Args...)
	} else {
		childLog("No binary path or command configured")
		return 1
	}

	// Environment variables
	env := cfg.EnvVars
	if len(env) == 0 {
		env = []string{"PATH=/bin:/usr/bin", "TERM=xterm"}
	}

	childLog(fmt.Sprintf("Handing off execution to %q with args %v", binaryPath, execArgs))

	execErr := unix.Exec(binaryPath, execArgs, env)
	if execErr != nil {
		childLog(fmt.Sprintf("KERNEL EXECVE FAILURE: %v", execErr))
		return 1
	}

	return 0
}
