//go:build linux

package child

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"syscall"

	"sandbox/sandbox/common"
	"sandbox/sandbox/config"
	"sandbox/sandbox/fs"
	"sandbox/sandbox/network"
	"sandbox/sandbox/resources"
	"sandbox/sandbox/security"

	"golang.org/x/sys/unix"
)

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

	if err := fs.IsolateRootFS(cfg.RootFSSource, cfg.BindMounts); err != nil {
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
	runtime.LockOSThread()

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

func dropCapabilities(requested []string) error {
	if len(requested) == 0 {
		return nil
	}
	drop := make([]bool, 64)
	all := false
	for _, raw := range requested {
		name := strings.ToUpper(strings.TrimSpace(raw))
		if name == "ALL" {
			all = true
			continue
		}
		number, ok := config.CapabilityNumber(name)
		if !ok {
			return fmt.Errorf("unknown capability %q", raw)
		}
		if number >= uintptr(len(drop)) {
			return fmt.Errorf("capability %q exceeds Linux v3 capability width", raw)
		}
		drop[number] = true
	}
	if all {
		last, err := lastCapability()
		if err != nil {
			return err
		}
		if last >= uintptr(len(drop)) {
			return fmt.Errorf("kernel capability %d exceeds Linux v3 capability width", last)
		}
		for number := uintptr(0); number <= last; number++ {
			drop[number] = true
		}
	}
	for number := uintptr(0); number < uintptr(len(drop)); number++ {
		if number == unix.CAP_SETPCAP || !drop[number] {
			continue
		}
		if err := unix.Prctl(unix.PR_CAPBSET_DROP, number, 0, 0, 0); err != nil {
			return fmt.Errorf("drop capability %d from bounding set: %w", number, err)
		}
	}
	if drop[unix.CAP_SETPCAP] {
		if err := unix.Prctl(unix.PR_CAPBSET_DROP, unix.CAP_SETPCAP, 0, 0, 0); err != nil {
			return fmt.Errorf("drop capability %d from bounding set: %w", unix.CAP_SETPCAP, err)
		}
	}

	var header unix.CapUserHeader
	header.Version = unix.LINUX_CAPABILITY_VERSION_3
	var data [2]unix.CapUserData
	if err := unix.Capget(&header, &data[0]); err != nil {
		return fmt.Errorf("read capability sets: %v", err)
	}
	for number, selected := range drop {
		if !selected {
			continue
		}
		word := number / 32
		bit := uint32(1) << (number % 32)
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

func lastCapability() (uintptr, error) {
	data, err := os.ReadFile("/proc/sys/kernel/cap_last_cap")
	if err != nil {
		return 0, fmt.Errorf("read kernel capability limit: %w", err)
	}
	value, err := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 32)
	if err != nil {
		return 0, fmt.Errorf("parse kernel capability limit: %w", err)
	}
	return uintptr(value), nil
}

func resourceBytes(value int, multiplier uint64, name string) (uint64, error) {
	if value < 0 || uint64(value) > ^uint64(0)/multiplier {
		return 0, fmt.Errorf("%s overflows the kernel limit", name)
	}
	return uint64(value) * multiplier, nil
}
