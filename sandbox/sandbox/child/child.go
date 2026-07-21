//go:build linux

package child

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"sandbox/sandbox/common"
	"sandbox/sandbox/config"
	"sandbox/sandbox/fs"
	"sandbox/sandbox/network"
	"sandbox/sandbox/resources"
	"sandbox/sandbox/security"

	"golang.org/x/sys/unix"
)

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

func Child(cfg config.Config, p2cRFd, c2pWFd int) int {
	childLog("Child process entered execution layer.")

	if err := waitForParentSetup(p2cRFd, c2pWFd); err != nil {
		childLog(fmt.Sprintf("PARENT HANDSHAKE FAILURE: %v", err))
		return 1
	}

	if err := resources.ApplyInitialStorageLimit(cfg.Storage); err != nil {
		childLog(fmt.Sprintf("RESOURCE FAILURE: %v", err))
		return 1
	}
	if cfg.MemoryLimitGB > 0 {
		memoryBytes := uint64(cfg.MemoryLimitGB) * gbToBytes
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

		// 2. STABILIZATION: Force Go runtime to yield and re-examine the network state
		// This prevents the netpoll panic when the namespace moves.
		time.Sleep(100 * time.Millisecond)
	}

	// ... (Rest of your function: CAPABILITIES, JAIL, SECCOMP, EXEC)

	if err := dropCapabilities(cfg.DropCapabilities); err != nil {
		childLog(fmt.Sprintf("SECURITY FAILURE: %v", err))
		return 1
	}

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
		if err := fs.WriteText("/etc/resolv.conf", strings.Join(lines, "\n")+"\n"); err != nil {
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
		if err := syscall.Chdir(cfg.WorkingDir); err != nil {
			childLog(fmt.Sprintf("JAIL FAILURE: working directory: %v", err))
			return 1
		}
	}

	if err := security.ApplySeccompFiltersCustom(cfg.SeccompDefaultAction, cfg.BlockedSyscalls); err != nil {
		childLog(fmt.Sprintf("SECCOMP FAILURE: %v", err))
		return 1
	}

	execArgs := cfg.CommandLine()
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
	ack := make([]byte, 1)
	if _, err := unix.Read(readFD, ack); err != nil {
		return fmt.Errorf("read ACK: %v", err)
	}
	if ack[0] != common.AckByte {
		return fmt.Errorf("invalid ACK byte %q", ack[0])
	}
	return nil
}

func dropCapabilities(capabilities []string) error {
	for _, name := range capabilities {
		capability, ok := capabilityNameToValue[name]
		if !ok {
			return fmt.Errorf("unknown capability %q", name)
		}
		if err := unix.Prctl(unix.PR_CAPBSET_DROP, capability, 0, 0, 0); err != nil {
			return fmt.Errorf("drop capability %q: %v", name, err)
		}
	}
	return nil
}
