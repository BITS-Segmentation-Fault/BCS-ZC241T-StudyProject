package network

import (
	"fmt"
)

type NetworkMode string

const (
	Host   NetworkMode = "host"
	None   NetworkMode = "none"
	Bridge NetworkMode = "bridge"
)

func (n NetworkMode) IsValid() bool {
	switch n {
	case Host, None, Bridge:
		return true
	default:
		return false
	}
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

func DefaultBridgeConfig() BridgeConfig {
	return BridgeConfig{
		BridgeName:     "sb0",
		Subnet:         "10.0.100.0/24",
		GatewayIP:      "10.0.100.1",
		ContainerIP:    "10.0.100.2",
		HostVethName:   "veth-sb0-h",
		NSVethName:     "veth-sb0-c",
		ContainerIface: "eth0",
		MTU:            1500,
	}
}
