//go:build linux

package child

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"

	"sandbox/sandbox/common"
	"sandbox/sandbox/fs"
	"sandbox/sandbox/network"
	"sandbox/sandbox/resources"
	"sandbox/sandbox/security"

	"golang.org/x/sys/unix"
)

var capabilityNameToValue = map[string]uintptr{
	"CAP_SYS_ADMIN":          unix.CAP_SYS_ADMIN,
	"CAP_NET_ADMIN":          unix.CAP_NET_ADMIN,
	"CAP_SYS_PTRACE":         unix.CAP_SYS_PTRACE,
	"CAP_SYS_MODULE":         unix.CAP_SYS_MODULE,
	"CAP_SYS_RAWIO":          unix.CAP_SYS_RAWIO,
	"CAP_SYS_BOOT":           unix.CAP_SYS_BOOT,
	"CAP_SYS_TIME":           unix.CAP_SYS_TIME,
	"CAP_SYSLOG":             unix.CAP_SYSLOG,
	"CAP_NET_RAW":            unix.CAP_NET_RAW,
	"CAP_NET_BIND_SERVICE":   unix.CAP_NET_BIND_SERVICE,
	"CAP_DAC_OVERRIDE":       unix.CAP_DAC_OVERRIDE,
	"CAP_CHOWN":              unix.CAP_CHOWN,
	"CAP_FOWNER":             unix.CAP_FOWNER,
	"CAP_KILL":               unix.CAP_KILL,
	"CAP_SETUID":             unix.CAP_SETUID,
	"CAP_SETGID":             unix.CAP_SETGID,
	"CAP_SETPCAP":            unix.CAP_SETPCAP,
	"CAP_MKNOD":              unix.CAP_MKNOD,
	"CAP_AUDIT_WRITE":        unix.CAP_AUDIT_WRITE,
	"CAP_AUDIT_CONTROL":      unix.CAP_AUDIT_CONTROL,
	"CAP_MAC_OVERRIDE":       unix.CAP_MAC_OVERRIDE,
	"CAP_MAC_ADMIN":          unix.CAP_MAC_ADMIN,
	"CAP_SYS_NICE":           unix.CAP_SYS_NICE,
	"CAP_SYS_RESOURCE":       unix.CAP_SYS_RESOURCE,
	"CAP_SYS_TTY_CONFIG":     unix.CAP_SYS_TTY_CONFIG,
	"CAP_IPC_LOCK":           unix.CAP_IPC_LOCK,
	"CAP_IPC_OWNER":          unix.CAP_IPC_OWNER,
	"CAP_NET_BROADCAST":      unix.CAP_NET_BROADCAST,
	"CAP_WAKE_ALARM":         unix.CAP_WAKE_ALARM,
	"CAP_BLOCK_SUSPEND":      unix.CAP_BLOCK_SUSPEND,
	"CAP_DAC_READ_SEARCH":    unix.CAP_DAC_READ_SEARCH,
	"CAP_FSETID":             unix.CAP_FSETID,
	"CAP_LINUX_IMMUTABLE":    unix.CAP_LINUX_IMMUTABLE,
	"CAP_SYS_CHROOT":         unix.CAP_SYS_CHROOT,
	"CAP_SYS_PACCT":          unix.CAP_SYS_PACCT,
	"CAP_LEASE":              unix.CAP_LEASE,
	"CAP_SETFCAP":            unix.CAP_SETFCAP,
	"CAP_AUDIT_READ":         unix.CAP_AUDIT_READ,
	"CAP_PERFMON":            unix.CAP_PERFMON,
	"CAP_BPF":                unix.CAP_BPF,
	"CAP_CHECKPOINT_RESTORE": unix.CAP_CHECKPOINT_RESTORE,
}

const gbToBytes = 1024 * 1024 * 1024

func childLog(msg string) {
	_, _ = syscall.Write(1, []byte(fmt.Sprintf("[CHILD DEBUG] %s\n", msg)))
}

func Child(p2cRFd, c2pWFd int) int {
	childLog("Child process entered execution layer.")

	if err := waitForParentSetup(p2cRFd, c2pWFd); err != nil {
		childLog(fmt.Sprintf("PARENT HANDSHAKE FAILURE: %v", err))
		return 1
	}
	readPipe := os.NewFile(uintptr(p2cRFd), "sandbox-config")
	cfg, err := common.ReceiveConfig(readPipe)
	_ = readPipe.Close()
	if err != nil {
		childLog(fmt.Sprintf("CONFIGURATION FAILURE: %v", err))
		return 1
	}
	if err := cfg.Validate(); err != nil {
		childLog(fmt.Sprintf("CONFIGURATION FAILURE: %v", err))
		return 1
	}
	if err := security.ValidateSyscallNames(cfg.BlockedSyscalls); err != nil {
		childLog(fmt.Sprintf("CONFIGURATION FAILURE: %v", err))
		return 1
	}

	if err := resources.ApplyFileSizeLimit(cfg.FileSizeLimitMB); err != nil {
		childLog(fmt.Sprintf("RESOURCE FAILURE: %v", err))
		return 1
	}
	if cfg.MemoryLimitGB > 0 {
		memoryBytes, err := resourceBytes(cfg.MemoryLimitGB, gbToBytes, "memory_limit_gb")
		if err != nil {
			childLog(fmt.Sprintf("RESOURCE FAILURE: %v", err))
			return 1
		}
		rlim := syscall.Rlimit{Cur: memoryBytes, Max: memoryBytes}
		if err := syscall.Setrlimit(unix.RLIMIT_AS, &rlim); err != nil {
			childLog(fmt.Sprintf("RESOURCE FAILURE: memory limit: %v", err))
			return 1
		}
	}

	// CLEANUP: Close all inherited host file descriptors after synchronization.
	for fd := 3; fd < 1024; fd++ {
		_ = syscall.Close(fd)
	}

	// Configure the moved interface only after the parent has acknowledged setup.
	if cfg.NetworkMode == network.Bridge {
		if err := network.ConfigureChildIface(cfg.BridgeConfig); err != nil {
			childLog(fmt.Sprintf("Bridge config failed: %v", err))
			return 1
		}
		childLog("Bridge interface configured.")

	}

	// ... (Rest of your function: CAPABILITIES, JAIL, SECCOMP, EXEC)

	rootfsTarget := cfg.RootFSSource
	if rootfsTarget == "" {
		rootfsTarget = "/var/lib/sandbox/rootfs"
	}
	if err := fs.IsolateRootFS(rootfsTarget, cfg.BindMounts); err != nil {
		childLog(fmt.Sprintf("JAIL FAILURE: %v", err))
		return 1
	}

	if len(cfg.DNSServers) > 0 {
		var lines []string
		for _, dns := range cfg.DNSServers {
			lines = append(lines, "nameserver "+dns)
		}
		if err := fs.WriteTextNoSymlinks("/etc/resolv.conf", strings.Join(lines, "\n")+"\n"); err != nil {
			childLog(fmt.Sprintf("NETWORK FAILURE: DNS configuration: %v", err))
			return 1
		}
	}

	if cfg.ReadOnlyRoot {
		if err := syscall.Mount("", "/", "", syscall.MS_REMOUNT|syscall.MS_RDONLY|syscall.MS_BIND, ""); err != nil {
			childLog(fmt.Sprintf("JAIL FAILURE: read-only root: %v", err))
			return 1
		}
	}

	rlim := syscall.Rlimit{Cur: uint64(cfg.MaxProcesses), Max: uint64(cfg.MaxProcesses)}
	if cfg.MaxProcesses > 0 {
		if err := syscall.Setrlimit(unix.RLIMIT_NPROC, &rlim); err != nil {
			childLog(fmt.Sprintf("RESOURCE FAILURE: process limit: %v", err))
			return 1
		}
	}

	if cfg.WorkingDir != "" {
		if err := fs.ChdirNoSymlinks(cfg.WorkingDir); err != nil {
			childLog(fmt.Sprintf("JAIL FAILURE: working directory: %v", err))
			return 1
		}
	}

	// Setup that needs namespace capabilities is complete. The executable gets
	// no effective, permitted, inheritable, ambient, or bounding capabilities.
	if err := dropCapabilities(cfg.DropCapabilities); err != nil {
		childLog(fmt.Sprintf("SECURITY FAILURE: %v", err))
		return 1
	}

	if err := security.ApplySeccompFiltersCustom(cfg.BlockedSyscallAction, cfg.BlockedSyscalls); err != nil {
		childLog(fmt.Sprintf("SECCOMP FAILURE: %v", err))
		return 1
	}

	execArgs := append([]string(nil), cfg.Command...)
	if len(execArgs) == 0 {
		childLog("EXEC FAILED: no command configured")
		return 1
	}

	binaryPath, err := exec.LookPath(execArgs[0])
	if err != nil {
		childLog(fmt.Sprintf("EXEC FAILED: %v", err))
		return 1
	}

	childLog(fmt.Sprintf("Handing off to %q", binaryPath))
	err = unix.Exec(binaryPath, execArgs, cfg.Environment(os.Environ()))
	childLog(fmt.Sprintf("EXEC FAILED: %v", err))
	return 1
}

func waitForParentSetup(readFD, writeFD int) error {
	if readFD <= 0 || writeFD <= 0 {
		return fmt.Errorf("invalid fixed handshake descriptors")
	}
	if _, err := unix.Write(writeFD, []byte{common.ReadyByte}); err != nil {
		return fmt.Errorf("send READY: %v", err)
	}
	return nil
}

func dropCapabilities(capabilities []string) error {
	mask := make(map[uintptr]struct{})
	for _, name := range capabilities {
		name = strings.ToUpper(strings.TrimSpace(name))
		if name == "ALL" {
			for capability := uintptr(0); capability <= lastCapability(); capability++ {
				mask[capability] = struct{}{}
			}
			continue
		}
		capability, ok := capabilityNameToValue[name]
		if !ok {
			return fmt.Errorf("unknown capability %q", name)
		}
		mask[capability] = struct{}{}
	}
	for capability := range mask {
		if err := unix.Prctl(unix.PR_CAPBSET_DROP, capability, 0, 0, 0); err != nil && err != unix.EPERM {
			return fmt.Errorf("drop capability %d from bounding set: %v", capability, err)
		}
	}

	var header unix.CapUserHeader
	header.Version = unix.LINUX_CAPABILITY_VERSION_3
	var data [2]unix.CapUserData
	if err := unix.Capget(&header, &data[0]); err != nil {
		return fmt.Errorf("read capability sets: %v", err)
	}
	for capability := range mask {
		word := capability / 32
		bit := uint32(1) << (capability % 32)
		data[word].Effective &^= bit
		data[word].Permitted &^= bit
		data[word].Inheritable &^= bit
	}
	if err := unix.Capset(&header, &data[0]); err != nil {
		return fmt.Errorf("clear capability sets: %v", err)
	}
	if err := unix.Prctl(unix.PR_CAP_AMBIENT, unix.PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0); err != nil {
		return fmt.Errorf("clear ambient capabilities: %v", err)
	}
	return nil
}

func lastCapability() uintptr {
	data, err := os.ReadFile("/proc/sys/kernel/cap_last_cap")
	if err == nil {
		if value, parseErr := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 32); parseErr == nil {
			return uintptr(value)
		}
	}
	return unix.CAP_LAST_CAP
}

func resourceBytes(value int, multiplier uint64, name string) (uint64, error) {
	if value < 0 || uint64(value) > ^uint64(0)/multiplier {
		return 0, fmt.Errorf("%s overflows the kernel limit", name)
	}
	return uint64(value) * multiplier, nil
}
