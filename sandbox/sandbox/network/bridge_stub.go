//go:build !linux

package network

import "errors"

func SetupParentBridge(cfg BridgeConfig) (*BridgeState, error) {
	return nil, errors.New("bridge networking is only supported on Linux")
}

func MoveVethToChild(state *BridgeState, pid int) error {
	return errors.New("bridge networking is only supported on Linux")
}

func ConfigureChildIface(cfg BridgeConfig) error {
	return errors.New("bridge networking is only supported on Linux")
}

func TeardownParentBridge(state *BridgeState) error {
	return nil
}
