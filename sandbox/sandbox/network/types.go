package network

import (
	"fmt"
	"net"
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
	if c.BridgeName == "" {
		return fmt.Errorf("bridge_name cannot be empty")
	}
	if _, _, err := net.ParseCIDR(c.Subnet); err != nil {
		return fmt.Errorf("invalid subnet %q: %v", c.Subnet, err)
	}
	if net.ParseIP(c.GatewayIP) == nil {
		return fmt.Errorf("invalid gateway IP %q", c.GatewayIP)
	}
	if net.ParseIP(c.ContainerIP) == nil {
		return fmt.Errorf("invalid container IP %q", c.ContainerIP)
	}
	if c.HostVethName == "" {
		return fmt.Errorf("host_veth_name cannot be empty")
	}
	if c.NSVethName == "" {
		return fmt.Errorf("ns_veth_name cannot be empty")
	}
	if c.ContainerIface == "" {
		return fmt.Errorf("container_iface cannot be empty")
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
	LinkSetMAC(name string, addr net.HardwareAddr) error
	LinkSetName(oldName, newName string) error
	AddrAdd(iface, ip string) error
	AddrDel(iface, ip string) error
}

var netlinkOps NetlinkOps

type BridgeState struct {
	Config BridgeConfig
}
