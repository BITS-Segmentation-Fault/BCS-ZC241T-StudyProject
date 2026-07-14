//go:build linux

package child

import (
	"fmt"
	"os"
	"strings"
	"syscall"
	"time"

	"sandbox/demo/common"
	"sandbox/demo/config"
	"sandbox/demo/fs"
	"sandbox/demo/network"
	"sandbox/demo/security"

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

func Child(cfg config.Config, p2cRFd uintptr, c2pWFd uintptr, hostUID int, hostGID int) int {
    
    os.Setenv("GODEBUG", "pidfd=0")
    os.Setenv("GOEXPERIMENT", "none")
	childLog("Child process entered execution layer.")

	// 1. NETWORK HANDSHAKE
	if cfg.NetworkMode == network.Bridge && p2cRFd != 0 && c2pWFd != 0 {
		childLog("Signalling readiness to parent...")
		if _, err := syscall.Write(int(c2pWFd), []byte{common.ReadyByte}); err != nil {
			childLog(fmt.Sprintf("Failed to signal READY: %v", err))
			return 1
		}
		
		ack := make([]byte, 1)
		if _, err := syscall.Read(int(p2cRFd), ack); err != nil {
			childLog(fmt.Sprintf("Failed to read ACK: %v", err))
			return 1
		}
		if ack[0] != common.AckByte {
			childLog("Invalid ACK received.")
			return 1
		}
		childLog("ACK received, proceeding.")
	}

	// 2. CLEANUP: Close inherited host file descriptors
	for fd := 3; fd < 1024; fd++ {
		if uintptr(fd) == p2cRFd || uintptr(fd) == c2pWFd {
			continue
		}
		_ = syscall.Close(fd)
	}

	// 3. NETWORK CONFIGURATION
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
	
	for _, capName := range cfg.DropCapabilities {
		if capVal, ok := capabilityNameToValue[capName]; ok {
			_ = unix.Prctl(unix.PR_CAPBSET_DROP, capVal, 0, 0, 0)
		}
	}

	rootfsTarget := cfg.RootFSSource
	if rootfsTarget == "" {
		rootfsTarget = "/var/lib/sandbox/rootfs"
	}
	if err := fs.IsolateRootFS(rootfsTarget, cfg.BindMounts); err != nil {
		childLog(fmt.Sprintf("JAIL FAILURE: %v", err))
		return 1
	}

	if cfg.ReadOnlyRoot {
		_ = syscall.Mount("", "/", "", syscall.MS_REMOUNT|syscall.MS_RDONLY|syscall.MS_BIND, "")
	}

	if len(cfg.DNSServers) > 0 {
		var lines []string
		for _, dns := range cfg.DNSServers {
			lines = append(lines, "nameserver "+dns)
		}
		_ = fs.WriteText("/etc/resolv.conf", strings.Join(lines, "\n")+"\n")
	}

	rlim := syscall.Rlimit{Cur: uint64(cfg.MaxProcesses), Max: uint64(cfg.MaxProcesses)}
	_ = syscall.Setrlimit(unix.RLIMIT_NPROC, &rlim)

	if err := security.ApplySeccompFiltersCustom(cfg.SeccompDefaultAction, cfg.BlockedSyscalls); err != nil {
		childLog(fmt.Sprintf("SECCOMP FAILURE: %v", err))
		return 1
	}

	binaryPath := cfg.BinaryPath
	execArgs := append([]string{binaryPath}, cfg.Args...)
	
	childLog(fmt.Sprintf("Handing off to %q", binaryPath))
	err := unix.Exec(binaryPath, execArgs, cfg.EnvVars)
	childLog(fmt.Sprintf("EXEC FAILED: %v", err))
	return 1
}
