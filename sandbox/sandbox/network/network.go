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

func ParseNetworkMode(input string) (NetworkMode, error) {

	mode := NetworkMode(input)
	if !mode.IsValid() {
		return "", fmt.Errorf("value_error: %q is not a valid NetworkMode (expected 'host', 'none', or 'bridge')", input)
	}

	return mode, nil
}
