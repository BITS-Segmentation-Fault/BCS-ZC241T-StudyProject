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

func (n NetworkMode) IsValid() bool { return n == Host || n == None || n == Bridge }

func (n NetworkMode) RequiresNetNS() bool { return n == None || n == Bridge }

var runCounter atomic.Uint32

func DefaultBridgeConfig() BridgeConfig {
	return BridgeConfig{
		Subnet:      "10.0.100.0/24",
		GatewayIP:   "10.0.100.1",
		ContainerIP: "10.0.100.2",
		MTU:         1500,
	}
}

func resourceNames() (bridge, hostVeth, nsVeth string) {
	suffix := fmt.Sprintf("%x%x", uint32(os.Getpid())&0xffff, runCounter.Add(1)&0xff)
	return "sb" + suffix, "vh" + suffix, "vc" + suffix
}
