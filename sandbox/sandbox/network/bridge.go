//go:build linux

package network

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"strconv"
)

type realNetlinkOps struct{}

// runIPCmd now forces the subprocess to ignore pidfd probes
func runIPCmd(args ...string) error {
	cmd := exec.Command("ip", args...)
	
	// FIX: Inject environment variables to disable pidfd and Go's runtime features 
	// that conflict with namespace switching.
	cmd.Env = append(os.Environ(), 
		"GODEBUG=pidfd=0", 
		"GOEXPERIMENT=none",
	)

	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("ip %v failed: %v\n%s", args, err, string(out))
	}
	return nil
}

// ... [Keep your existing BridgeAdd, BridgeDel, VethCreate, etc. functions exactly the same] ...

func (r *realNetlinkOps) BridgeAdd(name string) error {
	return runIPCmd("link", "add", name, "type", "bridge")
}

func (r *realNetlinkOps) BridgeDel(name string) error {
	return runIPCmd("link", "delete", name)
}

func (r *realNetlinkOps) VethCreate(name, peer string) error {
	return runIPCmd("link", "add", name, "type", "veth", "peer", "name", peer)
}

func (r *realNetlinkOps) VethDelete(name string) error {
	return runIPCmd("link", "delete", name)
}

func (r *realNetlinkOps) LinkSetMaster(link, master string) error {
	return runIPCmd("link", "set", link, "master", master)
}

func (r *realNetlinkOps) LinkSetNoMaster(link string) error {
	return runIPCmd("link", "set", link, "nomaster")
}

func (r *realNetlinkOps) LinkSetUp(name string) error {
	return runIPCmd("link", "set", name, "up")
}

func (r *realNetlinkOps) LinkSetDown(name string) error {
	return runIPCmd("link", "set", name, "down")
}

func (r *realNetlinkOps) LinkSetMAC(name string, addr net.HardwareAddr) error {
	return runIPCmd("link", "set", name, "address", addr.String())
}

func (r *realNetlinkOps) LinkSetName(oldName, newName string) error {
	return runIPCmd("link", "set", oldName, "name", newName)
}

func (r *realNetlinkOps) AddrAdd(iface, ip string) error {
	return runIPCmd("addr", "add", ip, "dev", iface)
}

func (r *realNetlinkOps) AddrDel(iface, ip string) error {
	return runIPCmd("addr", "del", ip, "dev", iface)
}

func init() {
	netlinkOps = &realNetlinkOps{}
}

// ... [Keep SetupParentBridge and MoveVethToChild as they were] ...

func SetupParentBridge(cfg BridgeConfig) (*BridgeState, error) {

	// Force cleanup before creating
    _ = runIPCmd("link", "delete", cfg.BridgeName)
    
    if err := cfg.Validate(); err != nil {
        return nil, fmt.Errorf("bridge config validation failed: %v", err)
    }

    log.Printf("[NETWORK] Creating bridge %q...", cfg.BridgeName)
    if err := netlinkOps.BridgeAdd(cfg.BridgeName); err != nil {
        return nil, fmt.Errorf("failed to create bridge: %v", err)
    }

    log.Printf("[NETWORK] Creating veth pair: %s <-> %s", cfg.HostVethName, cfg.NSVethName)
    if err := netlinkOps.VethCreate(cfg.HostVethName, cfg.NSVethName); err != nil {
        netlinkOps.BridgeDel(cfg.BridgeName)
        return nil, fmt.Errorf("failed to create veth pair: %v", err)
    }

    log.Printf("[NETWORK] Attaching %s to bridge %s", cfg.HostVethName, cfg.BridgeName)
    if err := netlinkOps.LinkSetMaster(cfg.HostVethName, cfg.BridgeName); err != nil {
        netlinkOps.VethDelete(cfg.HostVethName)
        netlinkOps.BridgeDel(cfg.BridgeName)
        return nil, fmt.Errorf("failed to attach veth to bridge: %v", err)
    }

    log.Printf("[NETWORK] Assigning IP %s/24 to bridge %s", cfg.GatewayIP, cfg.BridgeName)
    if err := netlinkOps.AddrAdd(cfg.BridgeName, cfg.GatewayIP+"/24"); err != nil {
        netlinkOps.LinkSetNoMaster(cfg.HostVethName)
        netlinkOps.VethDelete(cfg.HostVethName)
        netlinkOps.BridgeDel(cfg.BridgeName)
        return nil, fmt.Errorf("failed to assign bridge IP: %v", err)
    }

    log.Printf("[NETWORK] Bringing up bridge %s", cfg.BridgeName)
    if err := netlinkOps.LinkSetUp(cfg.BridgeName); err != nil {
        cleanupParentBridge(cfg)
        return nil, fmt.Errorf("failed to bring up bridge: %v", err)
    }

    log.Printf("[NETWORK] Bringing up host veth %s", cfg.HostVethName)
    if err := netlinkOps.LinkSetUp(cfg.HostVethName); err != nil {
        cleanupParentBridge(cfg)
        return nil, fmt.Errorf("failed to bring up host veth: %v", err)
    }

    log.Printf("[NETWORK] Bridge %q created with IP %s/24", cfg.BridgeName, cfg.GatewayIP)
    return &BridgeState{Config: cfg}, nil
}

func MoveVethToChild(pid int, cfg BridgeConfig) error {
    log.Printf("[NETWORK] Moving %s to child netns (pid %d)", cfg.NSVethName, pid)
    return runIPCmd("link", "set", cfg.NSVethName, "netns", strconv.Itoa(pid))
}

func ConfigureChildIface(cfg BridgeConfig) error {
	log.Printf("[NETWORK] Configuring interface inside child netns...")

	mac, err := GenerateRandomMAC(nil)
	if err != nil {
		return fmt.Errorf("failed to generate MAC: %v", err)
	}

	if err := netlinkOps.LinkSetMAC(cfg.NSVethName, mac); err != nil {
		return fmt.Errorf("failed to set MAC address: %v", err)
	}

	if err := netlinkOps.LinkSetName(cfg.NSVethName, cfg.ContainerIface); err != nil {
		return fmt.Errorf("failed to rename interface: %v", err)
	}

	if err := netlinkOps.AddrAdd(cfg.ContainerIface, cfg.ContainerIP+"/24"); err != nil {
		return fmt.Errorf("failed to assign IP: %v", err)
	}

	if err := netlinkOps.LinkSetUp(cfg.ContainerIface); err != nil {
		return fmt.Errorf("failed to bring up interface: %v", err)
	}

	if err := netlinkOps.LinkSetUp("lo"); err != nil {
		return fmt.Errorf("failed to bring up loopback: %v", err)
	}

	// Replaced inline exec.Command with runIPCmd to inherit the environment fix
	if err := runIPCmd("route", "add", "default", "via", cfg.GatewayIP); err != nil {
		return fmt.Errorf("failed to add default route: %v", err)
	}

	log.Printf("[NETWORK] Configured %s: IP %s/24, gw %s, MAC %s",
		cfg.ContainerIface, cfg.ContainerIP, cfg.GatewayIP, mac.String())
	return nil
}

// ... [Keep rest of the file as is] ...

func TeardownParentBridge(state *BridgeState) error {
    if state == nil {
        return nil
    }
    log.Printf("[NETWORK] Cleaning up bridge %q...", state.Config.BridgeName)
    cleanupParentBridge(state.Config)
    log.Printf("[NETWORK] Bridge teardown complete")
    return nil
}

func cleanupParentBridge(cfg BridgeConfig) {
    _ = netlinkOps.LinkSetNoMaster(cfg.HostVethName)
    _ = netlinkOps.VethDelete(cfg.HostVethName)
    _ = netlinkOps.BridgeDel(cfg.BridgeName)
}
