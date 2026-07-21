package network

import (
	"fmt"
	"net"
	"strings"
	"sync"
)

type BridgeConfig struct {
	BridgeName     string `yaml:"bridge_name"`
	Subnet         string `yaml:"subnet"`
	GatewayIP      string `yaml:"gateway_ip"`
	ContainerIP    string `yaml:"container_ip"`
	HostVethName   string `yaml:"host_veth_name"`
	NSVethName     string `yaml:"ns_veth_name"`
	ContainerIface string `yaml:"container_iface"`
	MTU            int    `yaml:"mtu"`
}

func (c BridgeConfig) Validate() error {
	if err := validateInterfaceName("bridge_name", c.BridgeName); err != nil {
		return err
	}
	if err := validateInterfaceName("host_veth_name", c.HostVethName); err != nil {
		return err
	}
	if err := validateInterfaceName("ns_veth_name", c.NSVethName); err != nil {
		return err
	}
	if err := validateInterfaceName("container_iface", c.ContainerIface); err != nil {
		return err
	}
	if c.BridgeName == c.HostVethName || c.BridgeName == c.NSVethName || c.HostVethName == c.NSVethName {
		return fmt.Errorf("bridge and veth names must be distinct")
	}
	ip, subnet, err := net.ParseCIDR(c.Subnet)
	if err != nil || ip.To4() == nil || subnet.IP.To4() == nil {
		return fmt.Errorf("invalid subnet %q", c.Subnet)
	}
	ones, bits := subnet.Mask.Size()
	if bits != 32 || ones < 1 || ones > 30 {
		return fmt.Errorf("subnet %q must leave usable host addresses", c.Subnet)
	}
	gateway := net.ParseIP(c.GatewayIP).To4()
	container := net.ParseIP(c.ContainerIP).To4()
	if gateway == nil {
		return fmt.Errorf("invalid gateway IP %q", c.GatewayIP)
	}
	if container == nil {
		return fmt.Errorf("invalid container IP %q", c.ContainerIP)
	}
	if !subnet.Contains(gateway) || !subnet.Contains(container) {
		return fmt.Errorf("gateway and container IPs must belong to subnet %q", c.Subnet)
	}
	if gateway.Equal(container) {
		return fmt.Errorf("gateway and container IPs must be distinct")
	}
	networkIP := subnet.IP.To4()
	broadcast := make(net.IP, net.IPv4len)
	for i := range broadcast {
		broadcast[i] = subnet.IP.To4()[i] | ^subnet.Mask[i]
	}
	if gateway.Equal(networkIP) || gateway.Equal(broadcast) || container.Equal(networkIP) || container.Equal(broadcast) {
		return fmt.Errorf("gateway and container IPs cannot be the subnet network or broadcast address")
	}
	if c.MTU < 576 || c.MTU > 65535 {
		return fmt.Errorf("mtu must be between 576 and 65535")
	}
	return nil
}

func validateInterfaceName(field, value string) error {
	if value == "" {
		return fmt.Errorf("%s cannot be empty", field)
	}
	if len(value) >= 16 {
		return fmt.Errorf("%s %q exceeds the Linux interface-name limit", field, value)
	}
	if strings.IndexByte(value, 0) >= 0 || strings.IndexFunc(value, func(r rune) bool { return r == '/' || r == ' ' || r == '\t' || r == '\n' }) >= 0 {
		return fmt.Errorf("%s %q contains an invalid character", field, value)
	}
	return nil
}

type NetlinkOps interface {
	BridgeAdd(name string) error
	BridgeDel(name string) error
	VethCreate(name, peer string) error
	VethDelete(name string) error
	LinkSetMaster(link, master string) error
	LinkSetNoMaster(link string) error
	LinkSetUp(name string) error
	LinkSetDown(name string) error
	LinkSetMTU(name string, mtu int) error
	LinkSetMAC(name string, addr net.HardwareAddr) error
	LinkSetName(oldName, newName string) error
	AddrAdd(iface, ip string) error
	AddrDel(iface, ip string) error
}

type FirewallOps interface {
	AddNAT(subnet, bridge, label string) error
	DeleteNAT(subnet, bridge, label string) error
	AddMetadataBlock(destination, label string) error
	DeleteMetadataBlock(destination, label string) error
}

type Operations struct {
	Netlink  NetlinkOps
	RunIP    func(args ...string) error
	Firewall FirewallOps
}

type BridgeManager struct {
	ops   Operations
	runID string
}

type BridgeState struct {
	Config  BridgeConfig
	manager *BridgeManager
	NAT     *NATState

	mu        sync.Mutex
	bridge    bool
	veth      bool
	attached  bool
	addressed bool
	cleaned   bool
}

type NATState struct {
	Config   BridgeConfig
	manager  *BridgeManager
	label    string
	metadata []string
	mu       sync.Mutex
	cleaned  bool
}
