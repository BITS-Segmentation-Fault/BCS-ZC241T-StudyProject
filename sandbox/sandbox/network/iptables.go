//go:build linux

package network

import (
	"fmt"
	"os/exec"
)

type realFirewallOps struct{}

func runFirewall(args ...string) error {
	cmd := exec.Command("iptables", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("iptables %v failed: %v\n%s", args, err, string(out))
	}
	return nil
}

func (r *realFirewallOps) AddNAT(subnet, bridge, label string) error {
	return runFirewall("-t", "nat", "-A", "POSTROUTING", "-s", subnet, "!", "-o", bridge, "-m", "comment", "--comment", label, "-j", "MASQUERADE")
}

func (r *realFirewallOps) DeleteNAT(subnet, bridge, label string) error {
	return runFirewall("-t", "nat", "-D", "POSTROUTING", "-s", subnet, "!", "-o", bridge, "-m", "comment", "--comment", label, "-j", "MASQUERADE")
}

func (r *realFirewallOps) AddMetadataBlock(destination, label string) error {
	return runFirewall("-A", "FORWARD", "-d", destination, "-m", "comment", "--comment", label, "-j", "DROP")
}

func (r *realFirewallOps) DeleteMetadataBlock(destination, label string) error {
	return runFirewall("-D", "FORWARD", "-d", destination, "-m", "comment", "--comment", label, "-j", "DROP")
}

func (m *BridgeManager) SetupNAT(cfg BridgeConfig) (*NATState, error) {
	if err := m.ops.Firewall.AddNAT(cfg.Subnet, cfg.BridgeName, m.runID); err != nil {
		return nil, fmt.Errorf("failed to add owned NAT rule: %v", err)
	}
	return &NATState{Config: cfg, manager: m, label: m.runID}, nil
}

func SetupNATForBridge(state *BridgeState, cfg BridgeConfig) error {
	if state == nil || state.manager == nil {
		return fmt.Errorf("cannot configure NAT without an owned bridge state")
	}
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("bridge config validation failed: %v", err)
	}
	natState, err := state.manager.SetupNAT(cfg)
	if err != nil {
		return err
	}
	state.NAT = natState
	return nil
}

func TeardownNATState(state *NATState) error {
	if state == nil || state.manager == nil {
		return nil
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.cleaned {
		return nil
	}
	var firstErr error
	if len(state.metadata) == 0 {
		firstErr = state.manager.ops.Firewall.DeleteNAT(state.Config.Subnet, state.Config.BridgeName, state.label)
	} else {
		for _, destination := range state.metadata {
			if err := state.manager.ops.Firewall.DeleteMetadataBlock(destination, state.label); err != nil && firstErr == nil {
				firstErr = err
			}
		}
	}
	if firstErr == nil {
		state.cleaned = true
	}
	return firstErr
}

func SetupNAT(cfg BridgeConfig) error {
	if err := CheckBridgePrerequisites(); err != nil {
		return err
	}
	_, err := NewBridgeManager(Operations{}).SetupNAT(cfg)
	return err
}

// TeardownNAT is retained for callers using the old API. New orchestration
// uses TeardownNATState, which can only remove a rule owned by this run.
func TeardownNAT(cfg BridgeConfig) error {
	if err := CheckBridgePrerequisites(); err != nil {
		return err
	}
	m := NewBridgeManager(Operations{})
	return m.ops.Firewall.DeleteNAT(cfg.Subnet, cfg.BridgeName, m.runID)
}

func (m *BridgeManager) BlockHostMetadata() (*NATState, error) {
	for _, destination := range []string{"169.254.169.254", "169.254.0.0/16"} {
		if err := m.ops.Firewall.AddMetadataBlock(destination, m.runID); err != nil {
			for _, rollbackDestination := range []string{"169.254.169.254", "169.254.0.0/16"} {
				if rollbackDestination == destination {
					break
				}
				_ = m.ops.Firewall.DeleteMetadataBlock(rollbackDestination, m.runID)
			}
			return nil, fmt.Errorf("failed to add metadata block: %v", err)
		}
	}
	return &NATState{manager: m, label: m.runID, metadata: []string{"169.254.169.254", "169.254.0.0/16"}}, nil
}

func BlockHostMetadata() error {
	if err := CheckBridgePrerequisites(); err != nil {
		return err
	}
	m := NewBridgeManager(Operations{})
	m.runID = "study-project-metadata"
	_, err := m.BlockHostMetadata()
	return err
}

func UnblockHostMetadata() error {
	if err := CheckBridgePrerequisites(); err != nil {
		return err
	}
	m := NewBridgeManager(Operations{})
	m.runID = "study-project-metadata"
	for _, destination := range []string{"169.254.169.254", "169.254.0.0/16"} {
		if err := m.ops.Firewall.DeleteMetadataBlock(destination, m.runID); err != nil {
			return err
		}
	}
	return nil
}
