//go:build linux

package parent

import (
	"log"
	"os"
	"os/exec"
	"syscall"
	"time"

	"sandbox/demo/common"
	"sandbox/demo/config"
	"sandbox/demo/network"
)

const childReadyTimeout = 10 * time.Second

func Parent(cfg config.Config) int {
	if os.Geteuid() != 0 {
		log.Println("[PRE-FLIGHT ERROR] Sandbox must be executed with root privileges (sudo).")
		return 1
	}

	var bridgeState *network.BridgeState
	var p2cR, p2cW, c2pR, c2pW *os.File

	if cfg.NetworkMode == network.Bridge {
		var err error
		bridgeState, err = network.SetupParentBridge(cfg.BridgeConfig)
		if err != nil {
			log.Printf("[NETWORK] Bridge setup failed: %v", err)
			return 1
		}

		if err := network.SetupNAT(cfg.BridgeConfig); err != nil {
			network.TeardownParentBridge(bridgeState)
			return 1
		}

		// Create pipes for sync
		p2cR, p2cW, _ = os.Pipe()
		c2pR, c2pW, _ = os.Pipe()
	}

	childArgs := []string{"-child"}
	if cfg.NetworkMode == network.Bridge {
		childArgs = append(childArgs, "--child-read-fd=3", "--child-write-fd=4")
	}
	childArgs = append(childArgs, os.Args[1:]...)

	cmd := exec.Command("/proc/self/exe", childArgs...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	// NAMESPACE ISOLATION: 
	// We move all flags here. The child will now inherit these namespaces 
	// at birth, avoiding the need for manual Unshare calls.
	cloneFlags := syscall.CLONE_NEWUSER | syscall.CLONE_NEWPID | syscall.CLONE_NEWNS | syscall.CLONE_NEWUTS
	if cfg.NetworkMode.RequiresNetNS() {
		cloneFlags |= syscall.CLONE_NEWNET
	}

	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags: uintptr(cloneFlags),
		UidMappings: []syscall.SysProcIDMap{
			{ContainerID: 0, HostID: os.Getuid(), Size: 1},
		},
		GidMappings: []syscall.SysProcIDMap{
			{ContainerID: 0, HostID: os.Getgid(), Size: 1},
		},
	}

	if cfg.NetworkMode == network.Bridge {
		cmd.ExtraFiles = []*os.File{p2cR, c2pW}
	}

	if err := cmd.Start(); err != nil {
		cleanupBridge(bridgeState, cfg)
		return 1
	}

	pid := cmd.Process.Pid
	
	// Bridge handshake
	if cfg.NetworkMode == network.Bridge {
		p2cR.Close()
		c2pW.Close()

		ready := make([]byte, 1)
		// Set a timeout read
		c2pR.SetReadDeadline(time.Now().Add(childReadyTimeout))
		if _, err := c2pR.Read(ready); err != nil || ready[0] != common.ReadyByte {
			_ = syscall.Kill(pid, syscall.SIGKILL)
			cleanupBridge(bridgeState, cfg)
			return 1
		}

		// Now move the network interface
		if err := network.MoveVethToChild(pid, cfg.BridgeConfig); err != nil {
			_ = syscall.Kill(pid, syscall.SIGKILL)
			cleanupBridge(bridgeState, cfg)
			return 1
		}

		// ACK the child
		_, _ = p2cW.Write([]byte{common.AckByte})
		p2cW.Close()
		c2pR.Close()
	}

	// Wait loop remains the same
	// ... (rest of your wait logic)
    return waitForChild(cmd, bridgeState, cfg)
}

func waitForChild(cmd *exec.Cmd, state *network.BridgeState, cfg config.Config) int {
    // Keep your existing Wait4/Signal logic here...
    return 0 
}

func cleanupBridge(state *network.BridgeState, cfg config.Config) {
	if state == nil { return }
	_ = network.TeardownNAT(cfg.BridgeConfig)
	_ = network.TeardownParentBridge(state)
}
