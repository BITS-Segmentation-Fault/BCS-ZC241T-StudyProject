//go:build linux

package parent

import (
	"log"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"

	"sandbox/sandbox/common"
	"sandbox/sandbox/config"
	"sandbox/sandbox/network"
	"sandbox/sandbox/resources"
	"sandbox/sandbox/rootfs"
	"sandbox/sandbox/security"
)

func Parent(cfg config.Config) int {
	if err := cfg.Validate(); err != nil {
		log.Printf("[PRE-FLIGHT ERROR] invalid configuration: %v", err)
		return 1
	}
	if err := security.ValidateSyscallNames(cfg.BlockedSyscalls); err != nil {
		log.Printf("[PRE-FLIGHT ERROR] invalid syscall policy: %v", err)
		return 1
	}
	cfg = snapshotEnvironment(cfg, os.Environ())
	resolvedRootFS, err := (rootfs.Provisioner{}).Resolve(cfg.RootFSSource)
	if err != nil {
		log.Printf("[PRE-FLIGHT ERROR] rootfs cannot be provisioned: %v", err)
		return 1
	}
	cfg.RootFSSource = resolvedRootFS
	resourceLimits, err := resources.PrepareResourceLimits(cfg.CPULimitPercent, cfg.MemoryLimitGB, cfg.MaxProcesses)
	if err != nil {
		log.Printf("[PRE-FLIGHT ERROR] resource limits cannot be provisioned: %v", err)
		return 1
	}
	defer func() {
		if err := resourceLimits.Cleanup(); err != nil {
			log.Printf("[RESOURCE] cgroup cleanup failed: %v", err)
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
		if err := network.SetupFirewallForBridge(bridgeState); err != nil {
			cleanupBridge(bridgeState)
			log.Printf("[NETWORK] firewall setup failed: %v", err)
			return 1
		}
	}

	p2cR, p2cW, err := os.Pipe()
	if err != nil {
		cleanupBridge(bridgeState)
		return 1
	}
	cmd := exec.Command("/proc/self/exe", "--internal-child")
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = internalChildEnvironment(cfg.EnvVars)
	cmd.ExtraFiles = []*os.File{p2cR}

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
		closeFiles(p2cR, p2cW)
		cleanupBridge(bridgeState)
		log.Printf("[PRE-FLIGHT ERROR] cannot start isolated child: %v", err)
		return 1
	}

	closeFiles(p2cR)

	if err := resourceLimits.Attach(cmd.Process.Pid); err != nil {
		terminateChild(cmd)
		closeFiles(p2cW)
		cleanupBridge(bridgeState)
		log.Printf("[RESOURCE] CPU cgroup setup failed: %v", err)
		return 1
	}

	if cfg.NetworkMode == network.Bridge {
		if err := network.MoveVethToChild(bridgeState, cmd.Process.Pid); err != nil {
			terminateChild(cmd)
			closeFiles(p2cW)
			cleanupBridge(bridgeState)
			log.Printf("[NETWORK] moving veth failed: %v", err)
			return 1
		}
	}

	if err := common.SendConfig(p2cW, cfg); err != nil {
		terminateChild(cmd)
		closeFiles(p2cW)
		cleanupBridge(bridgeState)
		log.Printf("[SANDBOX] configuration snapshot failed: %v", err)
		return 1
	}
	closeFiles(p2cW)
	return waitForChild(cmd, bridgeState, cfg)
}

func waitForChild(cmd *exec.Cmd, state *network.BridgeState, cfg config.Config) int {
	defer cleanupBridge(state)

	signals := make(chan os.Signal, 4)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT)
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

func snapshotEnvironment(cfg config.Config, hostEnvironment []string) config.Config {
	cfg.EnvVars = cfg.Environment(hostEnvironment)
	cfg.EnvWhitelist = nil
	return cfg
}

func internalChildEnvironment(environment []string) []string {
	for _, entry := range environment {
		key, _, ok := strings.Cut(entry, "=")
		if ok && key == "PATH" {
			return []string{entry}
		}
	}
	return []string{}
}

func cleanupBridge(state *network.BridgeState) {
	if state == nil {
		return
	}
	if err := network.TeardownParentBridge(state); err != nil {
		log.Printf("[NETWORK] bridge cleanup failed: %v", err)
	}
}
