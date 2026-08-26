//go:build linux

package network

import (
	"errors"
	"fmt"
	"os/exec"
)

type realFirewallOps struct{ path string }

func (r *realFirewallOps) run(args ...string) error {
	cmd := exec.Command(r.path, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %v failed: %w\n%s", r.path, args, err, string(out))
	}
	return nil
}

func (r *realFirewallOps) Add(rule []string) error    { return r.run(rule...) }
func (r *realFirewallOps) Delete(rule []string) error { return r.run(rule...) }

func SetupFirewallForBridge(state *BridgeState) error {
	if state == nil || state.manager == nil {
		return fmt.Errorf("cannot configure firewall without an owned bridge state")
	}
	return state.manager.setupFirewall(state)
}

func (m *bridgeManager) setupFirewall(state *BridgeState) error {
	if state == nil || state.manager != m {
		return fmt.Errorf("cannot configure firewall without an owned bridge state")
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	if !state.ownedBridge {
		return fmt.Errorf("bridge resources are no longer owned")
	}
	if len(state.firewall) != 0 {
		return fmt.Errorf("firewall state is already installed for this bridge")
	}
	rules := firewallRules(state.config.Subnet, state.bridge, m.runID)
	for _, rule := range rules {
		if err := m.ops.firewall.Add(rule.add); err != nil {
			rollback := removeFirewallRulesLocked(state, m.ops.firewall)
			return errors.Join(fmt.Errorf("install firewall rule %v: %w", rule.add, err), rollback)
		}
		state.firewall = append(state.firewall, rule)
	}
	return nil
}

func firewallRules(subnet, bridge, label string) []firewallRule {
	withComment := func(base []string, target string) []string {
		args := append([]string{}, base...)
		args = append(args, "-m", "comment", "--comment", label, "-j", target)
		return args
	}
	return []firewallRule{
		{add: withComment([]string{"-I", "FORWARD", "1", "-i", bridge}, "ACCEPT"), del: withComment([]string{"-D", "FORWARD", "-i", bridge}, "ACCEPT")},
		{add: withComment([]string{"-I", "FORWARD", "1", "-o", bridge, "-m", "conntrack", "--ctstate", "NEW"}, "REJECT"), del: withComment([]string{"-D", "FORWARD", "-o", bridge, "-m", "conntrack", "--ctstate", "NEW"}, "REJECT")},
		{add: withComment([]string{"-I", "FORWARD", "1", "-o", bridge, "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED"}, "ACCEPT"), del: withComment([]string{"-D", "FORWARD", "-o", bridge, "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED"}, "ACCEPT")},
		{add: withComment([]string{"-I", "INPUT", "1", "-i", bridge}, "REJECT"), del: withComment([]string{"-D", "INPUT", "-i", bridge}, "REJECT")},
		{add: withComment([]string{"-I", "FORWARD", "1", "-i", bridge, "-d", "169.254.0.0/16"}, "REJECT"), del: withComment([]string{"-D", "FORWARD", "-i", bridge, "-d", "169.254.0.0/16"}, "REJECT")},
		{add: withComment([]string{"-t", "nat", "-I", "POSTROUTING", "1", "-s", subnet, "!", "-o", bridge}, "MASQUERADE"), del: withComment([]string{"-t", "nat", "-D", "POSTROUTING", "-s", subnet, "!", "-o", bridge}, "MASQUERADE")},
	}
}

func removeFirewallRulesLocked(state *BridgeState, firewall firewallOps) error {
	var errs []error
	for i := len(state.firewall) - 1; i >= 0; i-- {
		rule := state.firewall[i]
		if err := firewall.Delete(rule.del); err != nil {
			errs = append(errs, fmt.Errorf("remove firewall rule %v: %w", rule.del, err))
		} else {
			state.firewall = append(state.firewall[:i], state.firewall[i+1:]...)
		}
	}
	return errors.Join(errs...)
}
