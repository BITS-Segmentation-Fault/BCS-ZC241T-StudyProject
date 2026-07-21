package network

import (
	"fmt"
	"os"
	"sync/atomic"
)

type NetworkMode string

const (
	Host   NetworkMode = "host"
	None   NetworkMode = "none"
	Bridge NetworkMode = "bridge"
)

func (n NetworkMode) IsValid() bool {
	return n == Host || n == None || n == Bridge
}

func (n NetworkMode) RequiresNetNS() bool {
	return n == None || n == Bridge
}

func ParseNetworkMode(input string) (NetworkMode, error) {
	mode := NetworkMode(input)
	if !mode.IsValid() {
		return "", fmt.Errorf("value_error: %q is not a valid NetworkMode (expected 'host', 'none', or 'bridge')", input)
	}
	return mode, nil
}

var runCounter atomic.Uint32

func DefaultBridgeConfig() BridgeConfig {
	suffix := fmt.Sprintf("%x%x", uint32(os.Getpid())&0xffff, runCounter.Add(1)&0xff)
	return BridgeConfig{
		BridgeName:     "sb" + suffix,
		Subnet:         "10.0.100.0/24",
		GatewayIP:      "10.0.100.1",
		ContainerIP:    "10.0.100.2",
		HostVethName:   "vh" + suffix,
		NSVethName:     "vc" + suffix,
		ContainerIface: "eth0",
		MTU:            1500,
	}
}
