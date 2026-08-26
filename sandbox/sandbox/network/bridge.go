//go:build linux

package network

import (
	"errors"
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
		return fmt.Errorf("ip %v failed: %w\n%s", args, err, string(out))
	}
	return nil
}

func runIPOutput(args ...string) ([]byte, error) {
	cmd := exec.Command("ip", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("ip %v failed: %w\n%s", args, err, string(out))
	}
	return out, nil
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
func (r *realNetlinkOps) LinkSetUp(name string) error { return runIPCmd("link", "set", name, "up") }
func (r *realNetlinkOps) LinkSetMTU(name string, mtu int) error {
	return runIPCmd("link", "set", name, "mtu", strconv.Itoa(mtu))
}
func (r *realNetlinkOps) LinkSetMAC(name string, addr []byte) error {
	return runIPCmd("link", "set", name, "address", net.HardwareAddr(addr).String())
}
func (r *realNetlinkOps) LinkSetName(oldName, newName string) error {
	return runIPCmd("link", "set", oldName, "name", newName)
}
func (r *realNetlinkOps) AddrAdd(iface, ip string) error {
	return runIPCmd("addr", "add", ip, "dev", iface)
}
func (r *realNetlinkOps) LinkNames() ([]string, error) {
	out, err := runIPOutput("-o", "link", "show")
	if err != nil {
		return nil, err
	}
	var names []string
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			name := strings.TrimSuffix(fields[1], ":")
			if strings.Contains(name, "@") {
				name = strings.SplitN(name, "@", 2)[0]
			}
			names = append(names, name)
		}
	}
	return names, nil
}

func defaultOperations() operations {
	return operations{netlink: &realNetlinkOps{}, runIP: runIPCmd, firewall: &realFirewallOps{}}
}

func newBridgeManager(ops operations) *bridgeManager {
	defaults := defaultOperations()
	if ops.netlink == nil {
		ops.netlink = defaults.netlink
	}
	if ops.runIP == nil {
		ops.runIP = defaults.runIP
	}
	if ops.firewall == nil {
		ops.firewall = defaults.firewall
	}
	return &bridgeManager{ops: ops, runID: fmt.Sprintf("study-project-sandbox-%x-%x", os.Getpid(), runCounter.Add(1))}
}

func (m *bridgeManager) setupParentBridge(cfg BridgeConfig) (*BridgeState, error) {
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("bridge config validation failed: %w", err)
	}
	bridge, hostVeth, nsVeth := resourceNames()
	state := &BridgeState{config: cfg, manager: m, bridge: bridge, hostVeth: hostVeth, nsVeth: nsVeth}
	if err := m.ops.netlink.BridgeAdd(bridge); err != nil {
		return nil, fmt.Errorf("failed to create bridge %q: %w", bridge, err)
	}
	state.ownedBridge = true
	if err := m.ops.netlink.VethCreate(hostVeth, nsVeth); err != nil {
		return nil, setupFailure(fmt.Errorf("failed to create veth pair: %w", err), state)
	}
	state.ownedVeth = true
	if err := m.ops.netlink.LinkSetMaster(hostVeth, bridge); err != nil {
		return nil, setupFailure(fmt.Errorf("failed to attach veth to bridge: %w", err), state)
	}
	prefix, _ := netipPrefix(cfg.Subnet)
	if err := m.ops.netlink.AddrAdd(bridge, cfg.GatewayIP+"/"+strconv.Itoa(prefix)); err != nil {
		return nil, setupFailure(fmt.Errorf("failed to assign bridge IP: %w", err), state)
	}
	if err := m.ops.netlink.LinkSetMTU(bridge, cfg.MTU); err != nil {
		return nil, setupFailure(fmt.Errorf("failed to set bridge MTU: %w", err), state)
	}
	if err := m.ops.netlink.LinkSetMTU(hostVeth, cfg.MTU); err != nil {
		return nil, setupFailure(fmt.Errorf("failed to set host veth MTU: %w", err), state)
	}
	if err := m.ops.netlink.LinkSetUp(bridge); err != nil {
		return nil, setupFailure(fmt.Errorf("failed to bring up bridge: %w", err), state)
	}
	if err := m.ops.netlink.LinkSetUp(hostVeth); err != nil {
		return nil, setupFailure(fmt.Errorf("failed to bring up host veth: %w", err), state)
	}
	return state, nil
}

func (m *bridgeManager) moveVethToChild(state *BridgeState, pid int) error {
	if state == nil || state.manager != m || !state.ownedVeth {
		return fmt.Errorf("veth is not owned by this bridge state")
	}
	return m.ops.runIP("link", "set", state.nsVeth, "netns", strconv.Itoa(pid))
}

func (m *bridgeManager) configureChildIface(cfg BridgeConfig) error {
	names, err := m.ops.netlink.LinkNames()
	if err != nil {
		return fmt.Errorf("enumerate child interfaces: %w", err)
	}
	var iface string
	for _, name := range names {
		if name == "lo" {
			continue
		}
		if iface != "" {
			return fmt.Errorf("expected exactly one child interface besides lo")
		}
		iface = name
	}
	if iface == "" {
		return fmt.Errorf("expected one child interface besides lo")
	}
	mac, err := generateRandomMAC(nil)
	if err != nil {
		return fmt.Errorf("generate MAC: %w", err)
	}
	if err := m.ops.netlink.LinkSetMAC(iface, mac); err != nil {
		return fmt.Errorf("set MAC address: %w", err)
	}
	if err := m.ops.netlink.LinkSetName(iface, "eth0"); err != nil {
		return fmt.Errorf("rename interface: %w", err)
	}
	prefix, _ := netipPrefix(cfg.Subnet)
	if err := m.ops.netlink.AddrAdd("eth0", cfg.ContainerIP+"/"+strconv.Itoa(prefix)); err != nil {
		return fmt.Errorf("assign IP: %w", err)
	}
	if err := m.ops.netlink.LinkSetMTU("eth0", cfg.MTU); err != nil {
		return fmt.Errorf("set container MTU: %w", err)
	}
	if err := m.ops.netlink.LinkSetUp("eth0"); err != nil {
		return fmt.Errorf("bring up container interface: %w", err)
	}
	if err := m.ops.netlink.LinkSetUp("lo"); err != nil {
		return fmt.Errorf("bring up loopback: %w", err)
	}
	if err := m.ops.runIP("route", "add", "default", "via", cfg.GatewayIP); err != nil {
		return fmt.Errorf("add default route: %w", err)
	}
	return nil
}

func (state *BridgeState) cleanup() error {
	if state == nil || state.manager == nil {
		return nil
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	var errs []error
	if state.ownedVeth {
		if err := state.manager.ops.netlink.VethDelete(state.hostVeth); err != nil {
			errs = append(errs, fmt.Errorf("delete veth %q: %w", state.hostVeth, err))
		} else if err == nil {
			state.ownedVeth = false
		}
	}
	if state.ownedBridge {
		if err := state.manager.ops.netlink.BridgeDel(state.bridge); err != nil {
			errs = append(errs, fmt.Errorf("delete bridge %q: %w", state.bridge, err))
		} else {
			state.ownedBridge = false
		}
	}
	return errors.Join(errs...)
}

func setupFailure(err error, state *BridgeState) error { return errors.Join(err, state.cleanup()) }

func (m *bridgeManager) teardownParentBridge(state *BridgeState) error { return state.cleanup() }

func SetupParentBridge(cfg BridgeConfig) (*BridgeState, error) {
	if err := CheckBridgePrerequisites(); err != nil {
		return nil, err
	}
	return newBridgeManager(operations{}).setupParentBridge(cfg)
}

func setupParentBridgeWithOps(cfg BridgeConfig, ops operations) (*BridgeState, error) {
	return newBridgeManager(ops).setupParentBridge(cfg)
}

func MoveVethToChild(state *BridgeState, pid int) error {
	if state == nil || state.manager == nil {
		return fmt.Errorf("cannot move veth without an owned bridge state")
	}
	return state.manager.moveVethToChild(state, pid)
}

func ConfigureChildIface(cfg BridgeConfig) error {
	return newBridgeManager(operations{}).configureChildIface(cfg)
}

func TeardownParentBridge(state *BridgeState) error {
	if state == nil {
		return nil
	}
	return errors.Join(teardownNATState(state.nat), state.manager.teardownParentBridge(state))
}

func CheckBridgePrerequisites() error {
	if !hasNetAdminCapability() {
		return fmt.Errorf("bridge mode requires effective CAP_NET_ADMIN for host link and NAT operations")
	}
	if _, err := exec.LookPath("ip"); err != nil {
		return fmt.Errorf("bridge mode requires the ip command: %w", err)
	}
	if _, err := exec.LookPath("iptables"); err != nil {
		return fmt.Errorf("bridge mode requires iptables: %w", err)
	}
	return nil
}

func hasNetAdminCapability() bool {
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "CapEff:") {
			value, err := strconv.ParseUint(strings.TrimSpace(strings.TrimPrefix(line, "CapEff:")), 16, 64)
			return err == nil && value&(uint64(1)<<12) != 0
		}
	}
	return false
}

func netipPrefix(value string) (int, error) {
	_, bits, err := net.ParseCIDR(value)
	if err != nil {
		return 0, err
	}
	prefix, _ := bits.Mask.Size()
	return prefix, nil
}
