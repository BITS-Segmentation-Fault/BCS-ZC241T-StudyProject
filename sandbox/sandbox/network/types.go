package network

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"strings"
	"sync"
)

type BridgeConfig struct {
	Subnet      string `yaml:"subnet"`
	GatewayIP   string `yaml:"gateway_ip"`
	ContainerIP string `yaml:"container_ip"`
	MTU         int    `yaml:"mtu"`
}

func (c BridgeConfig) Validate() error {
	prefix, err := netip.ParsePrefix(c.Subnet)
	if err != nil || !prefix.Addr().Is4() || prefix != prefix.Masked() {
		return fmt.Errorf("invalid canonical IPv4 subnet %q", c.Subnet)
	}
	bits := prefix.Bits()
	if bits < 1 || bits > 30 {
		return fmt.Errorf("subnet %q must leave usable host addresses", c.Subnet)
	}
	gateway, err := netip.ParseAddr(c.GatewayIP)
	if err != nil || !gateway.Is4() {
		return fmt.Errorf("invalid gateway IP %q", c.GatewayIP)
	}
	container, err := netip.ParseAddr(c.ContainerIP)
	if err != nil || !container.Is4() {
		return fmt.Errorf("invalid container IP %q", c.ContainerIP)
	}
	if !prefix.Contains(gateway) || !prefix.Contains(container) {
		return fmt.Errorf("gateway and container IPs must belong to subnet %q", c.Subnet)
	}
	if gateway == container {
		return fmt.Errorf("gateway and container IPs must be distinct")
	}
	first := prefix.Masked().Addr()
	firstValue := first.As4()
	networkValue := binary.BigEndian.Uint32(firstValue[:])
	mask := prefix.Bits()
	networkValue &= ^uint32(0) << uint(32-mask)
	last := netip.AddrFrom4(func() [4]byte {
		var value [4]byte
		binary.BigEndian.PutUint32(value[:], networkValue|^uint32(0)>>uint(mask))
		return value
	}())
	if gateway == first || gateway == last || container == first || container == last {
		return fmt.Errorf("gateway and container IPs cannot be the subnet network or broadcast address")
	}
	if c.MTU < 576 || c.MTU > 65535 {
		return fmt.Errorf("mtu must be between 576 and 65535")
	}
	return nil
}

type netlinkOps interface {
	BridgeAdd(name string) error
	BridgeDel(name string) error
	VethCreate(name, peer string) error
	VethDelete(name string) error
	LinkSetMaster(link, master string) error
	LinkSetUp(name string) error
	LinkSetMTU(name string, mtu int) error
	LinkSetMAC(name string, addr []byte) error
	LinkSetName(oldName, newName string) error
	AddrAdd(iface, ip string) error
	LinkNames() ([]string, error)
}

type firewallOps interface {
	AddNAT(subnet, bridge, label string) error
	DeleteNAT(subnet, bridge, label string) error
	AddMetadataBlock(destination, label string) error
	DeleteMetadataBlock(destination, label string) error
}

type operations struct {
	netlink  netlinkOps
	runIP    func(args ...string) error
	firewall firewallOps
}

type bridgeManager struct {
	ops   operations
	runID string
}

type BridgeState struct {
	config      BridgeConfig
	manager     *bridgeManager
	nat         *natState
	bridge      string
	hostVeth    string
	nsVeth      string
	mu          sync.Mutex
	ownedBridge bool
	ownedVeth   bool
	cleaned     bool
}

type natState struct {
	config   BridgeConfig
	manager  *bridgeManager
	bridge   string
	label    string
	metadata []string
	mu       sync.Mutex
	cleaned  bool
}

func validateInterfaceName(value string) error {
	if value == "" || len(value) >= 16 || strings.IndexByte(value, 0) >= 0 || strings.ContainsAny(value, "/ \t\n") {
		return fmt.Errorf("invalid interface name %q", value)
	}
	return nil
}
