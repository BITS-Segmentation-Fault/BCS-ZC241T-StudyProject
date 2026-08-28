//go:build linux

package network

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

type realNetlinkOps struct {
	ipPath    string
	writeFile func(string, []byte, os.FileMode) error
}

func runCommand(path string, args ...string) error {
	cmd := exec.Command(path, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %v failed: %w\n%s", path, args, err, string(out))
	}
	return nil
}

func runCommandOutput(path string, args ...string) ([]byte, error) {
	cmd := exec.Command(path, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("%s %v failed: %w\n%s", path, args, err, string(out))
	}
	return out, nil
}

func (r *realNetlinkOps) BridgeAdd(name string) error {
	return r.run("link", "add", name, "type", "bridge")
}
func (r *realNetlinkOps) BridgeDel(name string) error { return r.run("link", "delete", name) }
func (r *realNetlinkOps) VethCreate(name, peer string) error {
	return r.run("link", "add", name, "type", "veth", "peer", "name", peer)
}
func (r *realNetlinkOps) VethDelete(name string) error { return r.run("link", "delete", name) }
func (r *realNetlinkOps) LinkSetMaster(link, master string) error {
	return r.run("link", "set", link, "master", master)
}
func (r *realNetlinkOps) LinkSetUp(name string) error { return r.run("link", "set", name, "up") }
func (r *realNetlinkOps) LinkSetMTU(name string, mtu int) error {
	return r.run("link", "set", name, "mtu", strconv.Itoa(mtu))
}
func (r *realNetlinkOps) LinkSetMAC(name string, addr []byte) error {
	return r.run("link", "set", name, "address", net.HardwareAddr(addr).String())
}
func (r *realNetlinkOps) LinkSetName(oldName, newName string) error {
	return r.run("link", "set", oldName, "name", newName)
}
func (r *realNetlinkOps) AddrAdd(iface, ip string) error {
	return r.run("addr", "add", ip, "dev", iface)
}
func (r *realNetlinkOps) LinkNames() ([]string, error) {
	out, err := runCommandOutput(r.ipPath, "-o", "link", "show")
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

func (r *realNetlinkOps) run(args ...string) error { return runCommand(r.ipPath, args...) }

func (r *realNetlinkOps) DisableIPv6() error {
	writeFile := r.writeFile
	if writeFile == nil {
		writeFile = os.WriteFile
	}
	if err := writeFile("/proc/sys/net/ipv6/conf/all/disable_ipv6", []byte("1\n"), 0644); err != nil {
		return err
	}
	return writeFile("/proc/sys/net/ipv6/conf/default/disable_ipv6", []byte("1\n"), 0644)
}

func routePrefixes(path string) ([]routeInfo, error) {
	output, err := runCommandOutput(path, "-j", "-4", "route", "show", "table", "all")
	if err != nil {
		return nil, err
	}
	var entries []struct {
		Destination string `json:"dst"`
		Device      string `json:"dev"`
	}
	if err := json.Unmarshal(output, &entries); err != nil {
		return nil, fmt.Errorf("parse ip route JSON: %w", err)
	}
	var routes []routeInfo
	for _, entry := range entries {
		if entry.Destination == "default" {
			continue
		}
		if entry.Destination == "" {
			return nil, fmt.Errorf("route entry has no destination")
		}
		value := entry.Destination
		if !strings.Contains(value, "/") {
			value += "/32"
		}
		prefix, err := netip.ParsePrefix(value)
		if err != nil || !prefix.Addr().Is4() {
			return nil, fmt.Errorf("invalid IPv4 route destination %q", entry.Destination)
		}
		routes = append(routes, routeInfo{prefix: prefix, device: entry.Device})
	}
	return routes, nil
}

func defaultOperations() operations {
	ipPath, _ := resolveTrustedTool("ip")
	iptablesPath, _ := resolveTrustedTool("iptables")
	return operations{
		netlink:   &realNetlinkOps{ipPath: ipPath, writeFile: os.WriteFile},
		runIP:     func(args ...string) error { return runCommand(ipPath, args...) },
		routeList: func() ([]routeInfo, error) { return routePrefixes(ipPath) },
		firewall:  &realFirewallOps{path: iptablesPath},
	}
}

func resolveTrustedTool(name string) (string, error) {
	for _, dir := range []string{"/usr/sbin", "/usr/bin", "/sbin", "/bin"} {
		path := filepath.Join(dir, name)
		info, err := os.Stat(path)
		if err == nil && info.Mode().IsRegular() && info.Mode()&0111 != 0 {
			return path, nil
		}
	}
	return "", fmt.Errorf("trusted %s executable was not found", name)
}

func newBridgeManager(ops operations) *bridgeManager {
	defaults := defaultOperations()
	if ops.netlink == nil {
		ops.netlink = defaults.netlink
	}
	if ops.runIP == nil {
		ops.runIP = defaults.runIP
	}
	if ops.routeList == nil {
		ops.routeList = defaults.routeList
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
	if m.ops.routeList != nil {
		routes, err := m.ops.routeList()
		if err != nil {
			return nil, fmt.Errorf("inspect IPv4 routes before bridge setup: %w", err)
		}
		prefix, _ := netip.ParsePrefix(cfg.Subnet)
		for _, route := range routes {
			if route.prefix.Overlaps(prefix) {
				return nil, fmt.Errorf("bridge subnet %q overlaps existing route %q on %s", cfg.Subnet, route.prefix, route.device)
			}
		}
	}
	bridge, hostVeth, nsVeth, err := resourceNames(nil)
	if err != nil {
		return nil, err
	}
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
	prefixBits, _ := netipPrefix(cfg.Subnet)
	configuredPrefix, _ := netip.ParsePrefix(cfg.Subnet)
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
	if err := m.ops.runIP("addr", "add", cfg.GatewayIP+"/"+strconv.Itoa(prefixBits), "dev", bridge, "noprefixroute"); err != nil {
		return nil, setupFailure(fmt.Errorf("failed to assign bridge IP: %w", err), state)
	}
	if err := m.ops.runIP("route", "add", cfg.Subnet, "dev", bridge, "src", cfg.GatewayIP, "proto", "static"); err != nil {
		return nil, setupFailure(fmt.Errorf("failed to add bridge route: %w", err), state)
	}
	routes, err := m.ops.routeList()
	if err != nil {
		return nil, setupFailure(fmt.Errorf("inspect IPv4 routes after bridge route assignment: %w", err), state)
	}
	ownedRoute := false
	for _, route := range routes {
		if route.prefix == configuredPrefix && route.device == bridge {
			ownedRoute = true
		}
		if route.device != bridge && route.prefix.Overlaps(configuredPrefix) {
			return nil, setupFailure(fmt.Errorf("bridge subnet %q overlaps route %q on %s after route assignment", cfg.Subnet, route.prefix, route.device), state)
		}
	}
	if !ownedRoute {
		return nil, setupFailure(fmt.Errorf("bridge route %q is missing on bridge %q after route assignment", configuredPrefix, bridge), state)
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
	if err := m.ops.netlink.DisableIPv6(); err != nil {
		return fmt.Errorf("disable IPv6: %w", err)
	}
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
	if len(state.firewall) != 0 {
		if err := removeFirewallRulesLocked(state, state.manager.ops.firewall); err != nil {
			errs = append(errs, fmt.Errorf("remove firewall rules: %w", err))
		}
	}
	if state.ownedVeth {
		if err := deleteOwnedLink(state.manager.ops.netlink, state.hostVeth, state.manager.ops.netlink.VethDelete); err != nil {
			errs = append(errs, fmt.Errorf("delete veth %q: %w", state.hostVeth, err))
		} else {
			state.ownedVeth = false
		}
	}
	if state.ownedBridge {
		if err := deleteOwnedLink(state.manager.ops.netlink, state.bridge, state.manager.ops.netlink.BridgeDel); err != nil {
			errs = append(errs, fmt.Errorf("delete bridge %q: %w", state.bridge, err))
		} else {
			state.ownedBridge = false
		}
	}
	return errors.Join(errs...)
}

func deleteOwnedLink(ops netlinkOps, name string, deleteLink func(string) error) error {
	if err := deleteLink(name); err == nil {
		return nil
	} else {
		deleteErr := err
		names, inspectErr := ops.LinkNames()
		if inspectErr != nil {
			return errors.Join(deleteErr, fmt.Errorf("inspect link %q after deletion failed: %w", name, inspectErr))
		}
		for _, candidate := range names {
			if candidate == name {
				return deleteErr
			}
		}
		return nil
	}
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
	return state.cleanup()
}

func CheckBridgePrerequisites() error {
	if !bridgeCapabilityCheck() {
		return fmt.Errorf("bridge mode requires effective CAP_NET_ADMIN for host link and NAT operations")
	}
	for _, tool := range []string{"ip", "iptables"} {
		if _, err := bridgeToolResolver(tool); err != nil {
			return fmt.Errorf("bridge mode requires trusted %s: %w", tool, err)
		}
	}
	forwarding, err := bridgeReadFile("/proc/sys/net/ipv4/ip_forward")
	if err != nil {
		return fmt.Errorf("bridge mode cannot read IPv4 forwarding state: %w", err)
	}
	if strings.TrimSpace(string(forwarding)) != "1" {
		return fmt.Errorf("bridge mode requires IPv4 forwarding to be enabled")
	}
	return nil
}

var bridgeCapabilityCheck = hasNetAdminCapability
var bridgeToolResolver = resolveTrustedTool
var bridgeReadFile = os.ReadFile

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
