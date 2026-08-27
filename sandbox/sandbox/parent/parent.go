//go:build linux

package parent

import (
	"log"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"

	"sandbox/sandbox/config"
	"sandbox/sandbox/internal/ipc"
	"sandbox/sandbox/network"
	"sandbox/sandbox/resources"
	"sandbox/sandbox/rootfs"
	"sandbox/sandbox/security"
)

func Parent(cfg config.Config) (result int) {
	result = 1
	if err := cfg.Validate(); err != nil {
		log.Printf("[PRE-FLIGHT ERROR] invalid configuration: %v", err)
		return 1
	}
	if err := security.ValidateSyscallNames(cfg.BlockedSyscalls); err != nil {
		log.Printf("[PRE-FLIGHT ERROR] invalid syscall policy: %v", err)
		return 1
	}
	cfg = snapshotEnvironment(cfg, os.Environ())
	provisioner := rootfs.Provisioner{}
	var resolvedRootFS string
	var err error
	if cfg.RemoteRootFS != nil {
		remote := rootfs.RemoteSource{
			URL:           cfg.RemoteRootFS.URL,
			Architecture:  cfg.RemoteRootFS.Architecture,
			ArchiveSHA256: cfg.RemoteRootFS.ArchiveSHA256,
			TreeSHA256:    cfg.RemoteRootFS.TreeSHA256,
		}
		resolvedRootFS, err = provisioner.ResolveRemote(remote)
	} else {
		resolvedRootFS, err = provisioner.Resolve(cfg.RootFSSource)
	}
	if err != nil {
		log.Printf("[PRE-FLIGHT ERROR] rootfs cannot be provisioned: %v", err)
		return 1
	}
	cfg.RootFSSource = resolvedRootFS
	cfg.RemoteRootFS = nil
	signals := make(chan os.Signal, 4)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT)
	defer signal.Stop(signals)

	resourceLimits, err := resources.PrepareResourceLimits(cfg.CPULimitPercent, cfg.MemoryLimitGB, cfg.MaxProcesses)
	if err != nil {
		log.Printf("[PRE-FLIGHT ERROR] resource limits cannot be provisioned: %v", err)
		return 1
	}
	defer func() {
		if err := resourceLimits.Cleanup(); err != nil {
			log.Printf("[RESOURCE] cgroup cleanup failed: %v", err)
			if result == 0 {
				result = 1
			}
		}
	}()
	var bridgeState *network.BridgeState
	if cfg.NetworkMode == network.Bridge {
		bridgeState, err = network.SetupParentBridge(cfg.BridgeConfig)
		if err != nil {
			log.Printf("[NETWORK] Bridge setup failed: %v", err)
			return 1
		}
		defer func() {
			if err := network.TeardownParentBridge(bridgeState); err != nil {
				log.Printf("[NETWORK] bridge cleanup failed: %v", err)
				if result == 0 {
					result = 1
				}
			}
		}()
		if err := network.SetupFirewallForBridge(bridgeState); err != nil {
			log.Printf("[NETWORK] firewall setup failed: %v", err)
			return 1
		}
	}

	p2cR, p2cW, err := os.Pipe()
	if err != nil {
		log.Printf("[SANDBOX] configuration pipe creation failed: %v", err)
		return 1
	}
	defer closeFiles(p2cR, p2cW)
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
		log.Printf("[PRE-FLIGHT ERROR] cannot start isolated child: %v", err)
		return 1
	}

	closeFiles(p2cR)
	childReaped := false
	defer func() {
		if !childReaped {
			terminateChild(cmd)
		}
	}()

	if err := resourceLimits.Attach(cmd.Process.Pid); err != nil {
		log.Printf("[RESOURCE] aggregate resource attachment failed: %v", err)
		return 1
	}

	if cfg.NetworkMode == network.Bridge {
		if err := network.MoveVethToChild(bridgeState, cmd.Process.Pid); err != nil {
			log.Printf("[NETWORK] moving veth failed: %v", err)
			return 1
		}
	}

	if err := ipc.WriteConfig(p2cW, cfg); err != nil {
		log.Printf("[SANDBOX] configuration snapshot failed: %v", err)
		return 1
	}
	closeFiles(p2cW)
	result = waitForChild(cmd, signals)
	childReaped = true
	return result
}

func waitForChild(cmd *exec.Cmd, signals <-chan os.Signal) int {
	done := make(chan struct{})
	forwarded := make(chan struct{})
	go func() {
		defer close(forwarded)
		forwardSignals(cmd, signals, done)
	}()

	err := cmd.Wait()
	close(done)
	<-forwarded
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
