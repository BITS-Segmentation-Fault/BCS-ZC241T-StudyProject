//go:build !linux

package network

import "errors"

func SetupNAT(cfg BridgeConfig) error {
	return errors.New("NAT configuration is only supported on Linux")
}

func TeardownNAT(cfg BridgeConfig) error {
	return nil
}

func BlockHostMetadata() error {
	return errors.New("firewall configuration is only supported on Linux")
}

func UnblockHostMetadata() error {
	return nil
}
