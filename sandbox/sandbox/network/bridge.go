//go:build linux

package network

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

type realNetlinkOps struct{}

func runIPCmd(args ...string) error {
	cmd := exec.Command("ip", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("ip %v failed: %v\n%s", args, err, string(out))
	}
	return nil
}

func (r *realNetlinkOps) BridgeAdd(name string) error {
	return runIPCmd("link", "add", name, "type", "bridge")
}
func (r *realNetlinkOps) BridgeDel(name string) error { return runIPCmd("link", "delete", name) }
func (r *realNetlinkOps) VethCreate(name, peer string) error {
	return runIPCmd("link", "add", name, "type", "veth", "peer", "name", peer)
}
func (r *realNetlinkOps) VethDelete(name string) error { return runIPCmd("link", "delete", name) }
func (r *realNetlinkOps) LinkSetMaster(link, master string) error {
	return runIPCmd("link", "set", link, "master", master)
}
func (r *realNetlinkOps) LinkSetNoMaster(link string) error {
	return runIPCmd("link", "set", link, "nomaster")
}
func (r *realNetlinkOps) LinkSetUp(name string) error   { return runIPCmd("link", "set", name, "up") }
func (r *realNetlinkOps) LinkSetDown(name string) error { return runIPCmd("link", "set", name, "down") }
func (r *realNetlinkOps) LinkSetMTU(name string, mtu int) error {
	return runIPCmd("link", "set", name, "mtu", strconv.Itoa(mtu))
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

func defaultOperations() Operations {
	return Operations{Netlink: &realNetlinkOps{}, RunIP: runIPCmd, Firewall: &realFirewallOps{}}
}

func NewBridgeManager(ops Operations) *BridgeManager {
	defaults := defaultOperations()
	if ops.Netlink == nil {
		ops.Netlink = defaults.Netlink
	}
	if ops.RunIP == nil {
		ops.RunIP = defaults.RunIP
	}
	if ops.Firewall == nil {
		ops.Firewall = defaults.Firewall
	}
	return &BridgeManager{ops: ops, runID: fmt.Sprintf("study-project-sandbox-%x-%x", os.Getpid(), runCounter.Add(1))}
}

func (m *BridgeManager) SetupParentBridge(cfg BridgeConfig) (*BridgeState, error) {
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("bridge config validation failed: %v", err)
	}
	state := &BridgeState{Config: cfg, manager: m}
	if err := m.ops.Netlink.BridgeAdd(cfg.BridgeName); err != nil {
		return nil, fmt.Errorf("failed to create bridge %q: %v", cfg.BridgeName, err)
	}
	state.bridge = true
	if err := m.ops.Netlink.VethCreate(cfg.HostVethName, cfg.NSVethName); err != nil {
		_ = state.cleanup()
		return nil, fmt.Errorf("failed to create veth pair: %v", err)
	}
	state.veth = true
	if err := m.ops.Netlink.LinkSetMaster(cfg.HostVethName, cfg.BridgeName); err != nil {
		_ = state.cleanup()
		return nil, fmt.Errorf("failed to attach veth to bridge: %v", err)
	}
	state.attached = true
	prefix, _ := subnetPrefix(cfg.Subnet)
	if err := m.ops.Netlink.AddrAdd(cfg.BridgeName, cfg.GatewayIP+"/"+strconv.Itoa(prefix)); err != nil {
		_ = state.cleanup()
		return nil, fmt.Errorf("failed to assign bridge IP: %v", err)
	}
	state.addressed = true
	if err := m.ops.Netlink.LinkSetMTU(cfg.BridgeName, cfg.MTU); err != nil {
		_ = state.cleanup()
		return nil, fmt.Errorf("failed to set bridge MTU: %v", err)
	}
	if err := m.ops.Netlink.LinkSetMTU(cfg.HostVethName, cfg.MTU); err != nil {
		_ = state.cleanup()
		return nil, fmt.Errorf("failed to set host veth MTU: %v", err)
	}
	if err := m.ops.Netlink.LinkSetUp(cfg.BridgeName); err != nil {
		_ = state.cleanup()
		return nil, fmt.Errorf("failed to bring up bridge: %v", err)
	}
	if err := m.ops.Netlink.LinkSetUp(cfg.HostVethName); err != nil {
		_ = state.cleanup()
		return nil, fmt.Errorf("failed to bring up host veth: %v", err)
	}
	return state, nil
}

func (m *BridgeManager) MoveVethToChild(pid int, cfg BridgeConfig) error {
	return m.ops.RunIP("link", "set", cfg.NSVethName, "netns", strconv.Itoa(pid))
}

func (m *BridgeManager) ConfigureChildIface(cfg BridgeConfig) error {
	mac, err := GenerateRandomMAC(nil)
	if err != nil {
		return fmt.Errorf("generate MAC: %v", err)
	}
	if err := m.ops.Netlink.LinkSetMAC(cfg.NSVethName, mac); err != nil {
		return fmt.Errorf("set MAC address: %v", err)
	}
	if err := m.ops.Netlink.LinkSetName(cfg.NSVethName, cfg.ContainerIface); err != nil {
		return fmt.Errorf("rename interface: %v", err)
	}
	prefix, _ := subnetPrefix(cfg.Subnet)
	if err := m.ops.Netlink.AddrAdd(cfg.ContainerIface, cfg.ContainerIP+"/"+strconv.Itoa(prefix)); err != nil {
		return fmt.Errorf("assign IP: %v", err)
	}
	if err := m.ops.Netlink.LinkSetMTU(cfg.ContainerIface, cfg.MTU); err != nil {
		return fmt.Errorf("set container MTU: %v", err)
	}
	if err := m.ops.Netlink.LinkSetUp(cfg.ContainerIface); err != nil {
		return fmt.Errorf("bring up container interface: %v", err)
	}
	if err := m.ops.Netlink.LinkSetUp("lo"); err != nil {
		return fmt.Errorf("bring up loopback: %v", err)
	}
	if err := m.ops.RunIP("route", "add", "default", "via", cfg.GatewayIP); err != nil {
		return fmt.Errorf("add default route: %v", err)
	}
	return nil
}

func (state *BridgeState) cleanup() error {
	if state == nil || state.manager == nil {
		return nil
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.cleaned {
		return nil
	}
	var firstErr error
	if state.addressed {
		prefix, _ := subnetPrefix(state.Config.Subnet)
		if err := state.manager.ops.Netlink.AddrDel(state.Config.BridgeName, state.Config.GatewayIP+"/"+strconv.Itoa(prefix)); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if state.attached {
		if err := state.manager.ops.Netlink.LinkSetNoMaster(state.Config.HostVethName); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if state.veth {
		if err := state.manager.ops.Netlink.VethDelete(state.Config.HostVethName); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if state.bridge {
		if err := state.manager.ops.Netlink.BridgeDel(state.Config.BridgeName); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if firstErr == nil {
		state.cleaned = true
	}
	return firstErr
}

func (m *BridgeManager) TeardownParentBridge(state *BridgeState) error { return state.cleanup() }

func SetupParentBridge(cfg BridgeConfig) (*BridgeState, error) {
	if err := CheckBridgePrerequisites(); err != nil {
		return nil, err
	}
	return NewBridgeManager(Operations{}).SetupParentBridge(cfg)
}

func SetupParentBridgeWithOps(cfg BridgeConfig, ops Operations) (*BridgeState, error) {
	return NewBridgeManager(ops).SetupParentBridge(cfg)
}

func MoveVethToChild(pid int, cfg BridgeConfig) error {
	return NewBridgeManager(Operations{}).MoveVethToChild(pid, cfg)
}

func ConfigureChildIface(cfg BridgeConfig) error {
	return NewBridgeManager(Operations{}).ConfigureChildIface(cfg)
}

func TeardownParentBridge(state *BridgeState) error {
	if state == nil {
		return nil
	}
	if err := TeardownNATState(state.NAT); err != nil {
		_ = state.manager.TeardownParentBridge(state)
		return err
	}
	return state.manager.TeardownParentBridge(state)
}

func CheckBridgePrerequisites() error {
	if os.Geteuid() != 0 && !hasNetAdminCapability() {
		return fmt.Errorf("bridge mode requires root or CAP_NET_ADMIN for host link and NAT operations")
	}
	if _, err := exec.LookPath("ip"); err != nil {
		return fmt.Errorf("bridge mode requires the ip command: %v", err)
	}
	if _, err := exec.LookPath("iptables"); err != nil {
		return fmt.Errorf("bridge mode requires iptables: %v", err)
	}
	return nil
}

func hasNetAdminCapability() bool {
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "CapEff:") {
			continue
		}
		value, err := strconv.ParseUint(strings.TrimSpace(strings.TrimPrefix(line, "CapEff:")), 16, 64)
		return err == nil && value&(uint64(1)<<12) != 0
	}
	return false
}

func subnetPrefix(value string) (int, error) {
	_, network, err := net.ParseCIDR(value)
	if err != nil {
		return 0, err
	}
	prefix, _ := network.Mask.Size()
	return prefix, nil
}
