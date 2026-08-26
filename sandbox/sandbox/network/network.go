package network

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
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

func resourceNames(r io.Reader) (bridge, hostVeth, nsVeth string, err error) {
	if r == nil {
		r = rand.Reader
	}
	var random [6]byte
	if _, err := io.ReadFull(r, random[:]); err != nil {
		return "", "", "", fmt.Errorf("generate bridge resource names: %w", err)
	}
	suffix := hex.EncodeToString(random[:])
	return "sb" + suffix, "vh" + suffix, "vc" + suffix, nil
}
