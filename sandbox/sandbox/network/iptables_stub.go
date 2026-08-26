//go:build !linux

package network

import "errors"

func SetupFirewallForBridge(state *BridgeState) error {
	return errors.New("firewall configuration is only supported on Linux")
}
