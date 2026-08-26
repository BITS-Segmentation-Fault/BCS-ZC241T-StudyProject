//go:build linux

package parent

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"sandbox/sandbox/common"
	"sandbox/sandbox/config"
	"sandbox/sandbox/network"
	"sandbox/sandbox/resources"
	"sandbox/sandbox/security"
)

const childReadyTimeout = 10 * time.Second

func Parent(cfg config.Config) int {
	if err := cfg.Validate(); err != nil {
		log.Printf("[PRE-FLIGHT ERROR] invalid configuration: %v", err)
		return 1
	}
	if err := security.ValidateSyscallNames(cfg.BlockedSyscalls); err != nil {
		log.Printf("[PRE-FLIGHT ERROR] invalid syscall policy: %v", err)
		return 1
	}
	cpuLimit, err := resources.PrepareCPULimit(cfg.CPULimitPercent)
	if err != nil {
		log.Printf("[PRE-FLIGHT ERROR] CPU limit cannot be provisioned: %v", err)
		return 1
	}
	defer func() {
		if err := cpuLimit.Cleanup(); err != nil {
			log.Printf("[RESOURCE] CPU cgroup cleanup failed: %v", err)
		}
	}()
	var bridgeState *network.BridgeState
	if cfg.NetworkMode == network.Bridge {
		var err error
		bridgeState, err = network.SetupParentBridge(cfg.BridgeConfig)
		if err != nil {
			log.Printf("[NETWORK] Bridge setup failed: %v", err)
			return 1
		}
		if err := network.SetupNATForBridge(bridgeState, cfg.BridgeConfig); err != nil {
			cleanupBridge(bridgeState, cfg)
			log.Printf("[NETWORK] NAT setup failed: %v", err)
			return 1
		}
	}

	p2cR, p2cW, err := os.Pipe()
	if err != nil {
		cleanupBridge(bridgeState, cfg)
		return 1
	}
	c2pR, c2pW, err := os.Pipe()
	if err != nil {
		closeFiles(p2cR, p2cW)
		cleanupBridge(bridgeState, cfg)
		return 1
	}

	cmd := exec.Command("/proc/self/exe", "--internal-child")
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = runtimeEnvironment(os.Environ())
	cmd.ExtraFiles = []*os.File{p2cR, c2pW}

	cloneFlags := uintptr(syscall.CLONE_NEWUSER | syscall.CLONE_NEWPID | syscall.CLONE_NEWNS | syscall.CLONE_NEWUTS)
	if cfg.NetworkMode.RequiresNetNS() {
		cloneFlags |= syscall.CLONE_NEWNET
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags:                 cloneFlags,
		Setpgid:                    true,
		Pdeathsig:                  syscall.SIGKILL,
		GidMappingsEnableSetgroups: false,
		UidMappings:                []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getuid(), Size: 1}},
		GidMappings:                []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getgid(), Size: 1}},
	}

	if err := cmd.Start(); err != nil {
		closeFiles(p2cR, p2cW, c2pR, c2pW)
		cleanupBridge(bridgeState, cfg)
		log.Printf("[PRE-FLIGHT ERROR] cannot start isolated child: %v", err)
		return 1
	}

	// The parent retains only the write-to-child and read-from-child ends.
	closeFiles(p2cR, c2pW)
	if err := waitForReady(c2pR); err != nil {
		terminateChild(cmd)
		closeFiles(p2cW, c2pR)
		cleanupBridge(bridgeState, cfg)
		log.Printf("[SANDBOX] child readiness failed: %v", err)
		return 1
	}

	if err := cpuLimit.Attach(cmd.Process.Pid); err != nil {
		terminateChild(cmd)
		closeFiles(p2cW, c2pR)
		cleanupBridge(bridgeState, cfg)
		log.Printf("[RESOURCE] CPU cgroup setup failed: %v", err)
		return 1
	}

	if cfg.NetworkMode == network.Bridge {
		if err := network.MoveVethToChild(cmd.Process.Pid, cfg.BridgeConfig); err != nil {
			terminateChild(cmd)
			closeFiles(p2cW, c2pR)
			cleanupBridge(bridgeState, cfg)
			log.Printf("[NETWORK] moving veth failed: %v", err)
			return 1
		}
	}

	if err := common.SendConfig(p2cW, cfg); err != nil {
		terminateChild(cmd)
		closeFiles(p2cW, c2pR)
		cleanupBridge(bridgeState, cfg)
		log.Printf("[SANDBOX] configuration snapshot failed: %v", err)
		return 1
	}
	closeFiles(p2cW, c2pR)
	return waitForChild(cmd, bridgeState, cfg)
}

func waitForReady(file *os.File) error {
	defer file.SetReadDeadline(time.Time{})
	if err := file.SetReadDeadline(time.Now().Add(childReadyTimeout)); err != nil {
		return err
	}
	ready := make([]byte, 1)
	if _, err := file.Read(ready); err != nil {
		return err
	}
	if ready[0] != common.ReadyByte {
		return fmt.Errorf("unexpected readiness byte %q", ready[0])
	}
	return nil
}

func waitForChild(cmd *exec.Cmd, state *network.BridgeState, cfg config.Config) int {
	defer cleanupBridge(state, cfg)

	signals := make(chan os.Signal, 4)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	defer signal.Stop(signals)
	done := make(chan struct{})
	defer close(done)
	go forwardSignals(cmd, signals, done)

	err := cmd.Wait()
	if err == nil {
		return 0
	}
	if exitErr, ok := err.(*exec.ExitError); ok {
		if code := exitErr.ExitCode(); code >= 0 {
			return code
		}
		if status, ok := exitErr.Sys().(syscall.WaitStatus); ok && status.Signaled() {
			return 128 + int(status.Signal())
		}
	}
	log.Printf("[SANDBOX] child wait failed: %v", err)
	return 1
}

func forwardSignals(cmd *exec.Cmd, signals <-chan os.Signal, done <-chan struct{}) {
	for {
		select {
		case <-done:
			return
		case received := <-signals:
			sig, ok := received.(syscall.Signal)
			if ok && cmd.Process != nil {
				_ = syscall.Kill(-cmd.Process.Pid, sig)
			}
		}
	}
}

func terminateChild(cmd *exec.Cmd) {
	if cmd.Process != nil {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
	_ = cmd.Wait()
}

func closeFiles(files ...*os.File) {
	for _, file := range files {
		if file != nil {
			_ = file.Close()
		}
	}
}

func runtimeEnvironment(environment []string) []string {
	const key = "GODEBUG="
	updated := make([]string, 0, len(environment)+1)
	found := false
	for _, entry := range environment {
		if strings.HasPrefix(entry, key) {
			if !found {
				updated = append(updated, key+"pidfd=0")
				found = true
			}
			continue
		}
		updated = append(updated, entry)
	}
	if !found {
		updated = append(updated, key+"pidfd=0")
	}
	return updated
}

func cleanupBridge(state *network.BridgeState, cfg config.Config) {
	if state == nil {
		return
	}
	_ = network.TeardownParentBridge(state)
}
