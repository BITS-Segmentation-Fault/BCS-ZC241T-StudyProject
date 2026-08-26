//go:build linux

package child

import (
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"syscall"

	"sandbox/sandbox/config"
	"sandbox/sandbox/fs"
	"sandbox/sandbox/internal/ipc"
	"sandbox/sandbox/network"
	"sandbox/sandbox/resources"
	"sandbox/sandbox/security"

	"golang.org/x/sys/unix"
)

func childLog(msg string) {
	_, _ = fmt.Fprintln(os.Stderr, msg)
}

func Child(p2cRFd int) int {
	readPipe := os.NewFile(uintptr(p2cRFd), "sandbox-config")
	cfg, err := ipc.ReadConfig(readPipe)
	_ = readPipe.Close()
	if err != nil {
		childLog(fmt.Sprintf("CONFIGURATION FAILURE: %v", err))
		return 1
	}
	if err := resources.ApplyFileSizeLimit(cfg.FileSizeLimitMB); err != nil {
		childLog(fmt.Sprintf("RESOURCE FAILURE: %v", err))
		return 1
	}

	if cfg.NetworkMode == network.Bridge {
		if err := network.ConfigureChildIface(cfg.BridgeConfig); err != nil {
			childLog(fmt.Sprintf("Bridge config failed: %v", err))
			return 1
		}
	}

	if err := fs.IsolateRootFS(cfg.RootFSSource, cfg.BindMounts, cfg.ReadOnlyRoot, cfg.DNSServers); err != nil {
		childLog(fmt.Sprintf("JAIL FAILURE: %v", err))
		return 1
	}

	if err := os.Chdir(cfg.WorkingDir); err != nil {
		childLog(fmt.Sprintf("JAIL FAILURE: working directory: %v", err))
		return 1
	}
	runtime.LockOSThread()

	// Setup that needs namespace capabilities is complete. The executable gets
	// no effective, permitted, inheritable, ambient, or bounding capabilities.
	if err := dropCapabilities(cfg.DropCapabilities); err != nil {
		childLog(fmt.Sprintf("SECURITY FAILURE: %v", err))
		return 1
	}

	if err := security.ApplySeccompFilter(cfg.BlockedSyscallAction, cfg.BlockedSyscalls); err != nil {
		childLog(fmt.Sprintf("SECCOMP FAILURE: %v", err))
		return 1
	}

	binaryPath, err := exec.LookPath(cfg.Command[0])
	if err != nil {
		childLog(fmt.Sprintf("EXEC FAILED: %v", err))
		return 1
	}

	return runInit(binaryPath, cfg.Command, cfg.EnvVars)
}

// runInit keeps the payload in the namespace init process group. The parent
// therefore reaches both processes with the same group-directed signal.
func runInit(binary string, command, environment []string) int {
	signals := make(chan os.Signal, 8)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT)
	defer signal.Stop(signals)

	payload := exec.Command(binary, command[1:]...)
	payload.Stdin, payload.Stdout, payload.Stderr = os.Stdin, os.Stdout, os.Stderr
	payload.Env = environment
	if err := payload.Start(); err != nil {
		childLog(fmt.Sprintf("EXEC FAILED: %v", err))
		return 127
	}
	deliverQueuedSignals(signals, payload.Process.Pid)
	status, err := reapUntilPayloadExits(payload.Process.Pid)
	_ = payload.Process.Release()
	if err != nil {
		childLog(fmt.Sprintf("INIT wait failed: %v", err))
		return 1
	}
	if status.Exited() {
		return status.ExitStatus()
	}
	if status.Signaled() {
		return 128 + int(status.Signal())
	}
	return 1
}

func deliverQueuedSignals(signals <-chan os.Signal, payloadPID int) {
	for {
		select {
		case received := <-signals:
			if sig, ok := received.(syscall.Signal); ok {
				_ = syscall.Kill(payloadPID, sig)
			}
		default:
			return
		}
	}
}

func reapUntilPayloadExits(payloadPID int) (syscall.WaitStatus, error) {
	for {
		var status syscall.WaitStatus
		pid, err := syscall.Wait4(-1, &status, 0, nil)
		if err == syscall.EINTR {
			continue
		}
		if err != nil {
			return 0, err
		}
		if pid == payloadPID {
			return status, nil
		}
	}
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
