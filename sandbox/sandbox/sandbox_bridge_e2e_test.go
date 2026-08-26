package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"sandbox/sandbox/network"
)

const bridgeUnavailablePrefix = "SANDBOX_BRIDGE_E2E_UNAVAILABLE: "

// This target is intentionally opt-in: it runs the bridge lifecycle inside
// an isolated outer network namespace. CI's privileged job sets
// SANDBOX_PRIVILEGED_E2E=1 and SANDBOX_E2E_REQUIRED=1 so missing
// prerequisites become failures there.
func TestSandboxPrivilegedBridgeLifecycle(t *testing.T) {
	if os.Getenv("SANDBOX_PRIVILEGED_E2E") != "1" {
		t.Skip("privileged bridge E2E requires SANDBOX_PRIVILEGED_E2E=1")
	}
	if os.Getenv("SANDBOX_BRIDGE_E2E_INNER") != "1" {
		if _, err := exec.LookPath("unshare"); err != nil {
			skipOrFail(t, "unshare is unavailable for the isolated bridge E2E")
		}
		command := exec.Command("unshare", "-Urn", os.Args[0], "-test.run=TestSandboxPrivilegedBridgeLifecycle", "-test.v")
		command.Env = withEnvironment(os.Environ(), "SANDBOX_BRIDGE_E2E_INNER", "1")
		output, err := command.CombinedOutput()
		if reason, ok := bridgeUnavailableReason(string(output)); ok {
			skipOrFail(t, reason)
		}
		if err != nil {
			if strings.Contains(string(output), "Operation not permitted") || strings.Contains(string(output), "unshare") {
				skipOrFail(t, string(output))
			}
			t.Fatalf("isolated bridge E2E failed: %v\n%s", err, output)
		}
		return
	}
	if err := os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1\n"), 0644); err != nil {
		if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) || errors.Is(err, syscall.EROFS) {
			skipBridgeUnavailable(t, fmt.Sprintf("isolated IPv4 forwarding is unavailable: %v", err))
		}
		t.Fatalf("enable IPv4 forwarding in isolated namespace: %v", err)
	}
	if err := network.CheckBridgePrerequisites(); err != nil {
		if bridgePrerequisiteUnavailable(err) {
			skipBridgeUnavailable(t, err.Error())
		}
		t.Fatalf("bridge prerequisite check failed: %v", err)
	}
	sandbox := sandboxTestBinary(t)
	probe := probeTestBinary(t)
	rootfs := makeProbeRootfs(t, probe)
	linksBefore := bridgeCommandOutput(t, "ip", "-o", "link", "show")
	firewallSave := trustedBridgeTool(t, "iptables-save")
	firewallBefore := normalizeFirewallSnapshot(bridgeCommandOutputPath(t, firewallSave))
	firstConfig := writeSandboxConfig(t, rootfs, "bridge", "--sleep=10")
	first := exec.Command(sandbox, "--config", firstConfig)
	var firstOutput bytes.Buffer
	first.Stdout, first.Stderr = &firstOutput, &firstOutput
	if err := first.Start(); err != nil {
		t.Fatalf("start first bridge sandbox: %v", err)
	}
	secondConfig := writeSandboxConfig(t, rootfs, "bridge", "--sleep=10")
	second := exec.Command(sandbox, "--config", secondConfig,
		"--bridge-subnet", "10.0.101.0/24",
		"--bridge-gateway", "10.0.101.1",
		"--bridge-container-ip", "10.0.101.2")
	var secondOutput bytes.Buffer
	second.Stdout, second.Stderr = &secondOutput, &secondOutput
	if err := second.Start(); err != nil {
		_ = first.Process.Kill()
		_ = first.Wait()
		t.Fatalf("start second bridge sandbox: %v", err)
	}
	t.Cleanup(func() {
		_ = first.Process.Kill()
		_ = second.Process.Kill()
		_ = first.Wait()
		_ = second.Wait()
	})
	expectations := []bridgeFirewallExpectation{
		{subnet: "10.0.100.0/24"},
		{subnet: "10.0.101.0/24"},
	}
	if err := waitForBridgeRules(firewallSave, expectations); err != nil {
		t.Fatalf("bridge firewall rules were not installed: %v\n%s\n%s", err, firstOutput.String(), secondOutput.String())
	}
	linkNames := parseLinkNames(bridgeCommandOutput(t, "ip", "-o", "link", "show"))
	var bridges []string
	for _, name := range linkNames {
		if strings.HasPrefix(name, "sb") {
			bridges = append(bridges, name)
		}
	}
	if len(bridges) != 2 {
		t.Fatalf("bridge links = %v, want two owned bridges", bridges)
	}
	_ = first.Process.Signal(os.Interrupt)
	_ = second.Process.Signal(os.Interrupt)
	firstErr := first.Wait()
	secondErr := second.Wait()
	if firstErr == nil || secondErr == nil {
		t.Fatalf("sleeping bridge sandboxes did not terminate: first=%v second=%v", firstErr, secondErr)
	}
	assertBridgePayload(t, firstOutput.String(), "10.0.100.2/24", "10.0.100.1")
	assertBridgePayload(t, secondOutput.String(), "10.0.101.2/24", "10.0.101.1")
	linksAfter := bridgeCommandOutput(t, "ip", "-o", "link", "show")
	if string(linksBefore) != string(linksAfter) {
		t.Fatalf("host links changed across bridge lifecycle:\nbefore=%safter=%s", linksBefore, linksAfter)
	}
	firewallAfter := normalizeFirewallSnapshot(bridgeCommandOutputPath(t, firewallSave))
	if strings.Contains(string(firewallAfter), "study-project-sandbox") || string(firewallBefore) != string(firewallAfter) {
		t.Fatalf("owned firewall state was not cleaned up")
	}
}

type bridgeFirewallExpectation struct {
	subnet string
}

func waitForBridgeRules(path string, expectations []bridgeFirewallExpectation) error {
	ipPath, err := resolveBridgeTestTool("ip")
	if err != nil {
		return err
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		firewall, firewallErr := exec.Command(path).CombinedOutput()
		links, linksErr := exec.Command(ipPath, "-o", "link", "show").CombinedOutput()
		if firewallErr == nil && linksErr == nil && bridgeFirewallPoliciesPresent(firewall, parseLinkNames(links), expectations) {
			return nil
		}
		time.Sleep(25 * time.Millisecond)
	}
	return fmt.Errorf("timed out waiting for owned firewall rules")
}

func bridgeFirewallPoliciesPresent(data []byte, links []string, expectations []bridgeFirewallExpectation) bool {
	linkSet := make(map[string]bool, len(links))
	for _, link := range links {
		linkSet[link] = true
	}
	rules := firewallRuleLines(data)
	for _, expectation := range expectations {
		bridge, label, ok := findBridgeFirewallIdentity(rules, expectation.subnet)
		if !ok || !linkSet[bridge] {
			return false
		}
		for _, want := range expectedBridgeFirewallRules(bridge, expectation.subnet, label) {
			if !hasFirewallRule(rules, want) {
				return false
			}
		}
	}
	return true
}

func firewallRuleLines(data []byte) [][]string {
	var rules [][]string
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) > 0 && fields[0] == "-A" {
			rules = append(rules, fields)
		}
	}
	return rules
}

func findBridgeFirewallIdentity(rules [][]string, subnet string) (string, string, bool) {
	for _, rule := range rules {
		if len(rule) == 13 && rule[0] == "-A" && rule[1] == "POSTROUTING" &&
			rule[2] == "-s" && rule[3] == subnet && rule[4] == "!" && rule[5] == "-o" &&
			rule[7] == "-m" && rule[8] == "comment" && rule[9] == "--comment" &&
			rule[11] == "-j" && rule[12] == "MASQUERADE" {
			return rule[6], rule[10], true
		}
	}
	return "", "", false
}

func expectedBridgeFirewallRules(bridge, subnet, label string) [][]string {
	comment := []string{"-m", "comment", "--comment", label}
	withComment := func(base []string, target string) []string {
		return append(append(append([]string(nil), base...), comment...), "-j", target)
	}
	return [][]string{
		withComment([]string{"-A", "FORWARD", "-i", bridge}, "ACCEPT"),
		withComment([]string{"-A", "FORWARD", "-o", bridge, "-m", "conntrack", "--ctstate", "NEW"}, "REJECT"),
		withComment([]string{"-A", "FORWARD", "-o", bridge, "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED"}, "ACCEPT"),
		withComment([]string{"-A", "INPUT", "-i", bridge}, "REJECT"),
		withComment([]string{"-A", "FORWARD", "-i", bridge, "-d", "169.254.0.0/16"}, "REJECT"),
		withComment([]string{"-A", "POSTROUTING", "-s", subnet, "!", "-o", bridge}, "MASQUERADE"),
	}
}

func hasFirewallRule(rules [][]string, want []string) bool {
	for _, rule := range rules {
		if strings.Join(rule, " ") == strings.Join(want, " ") {
			return true
		}
	}
	return false
}

func parseLinkNames(data []byte) []string {
	var names []string
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		name := strings.TrimSuffix(fields[1], ":")
		if at := strings.IndexByte(name, '@'); at >= 0 {
			name = name[:at]
		}
		names = append(names, name)
	}
	return names
}

func resolveBridgeTestTool(name string) (string, error) {
	for _, dir := range []string{"/usr/sbin", "/usr/bin", "/sbin", "/bin"} {
		path := filepath.Join(dir, name)
		if info, err := os.Stat(path); err == nil && info.Mode().IsRegular() && info.Mode()&0111 != 0 {
			return path, nil
		}
	}
	return "", fmt.Errorf("trusted %s executable was not found", name)
}

func assertBridgePayload(t *testing.T, output, ipv4, gateway string) {
	t.Helper()
	if line := findLine(output, "interfaces="); line != "interfaces=eth0,lo" {
		t.Fatalf("interfaces = %q, want eth0,lo\n%s", line, output)
	}
	if line := findLine(output, "ipv4=eth0="); line != "ipv4=eth0="+ipv4 {
		t.Fatalf("IPv4 address = %q, want %s\n%s", line, "ipv4=eth0="+ipv4, output)
	}
	if line := findLine(output, "mtu=eth0="); line != "mtu=eth0=1500" {
		t.Fatalf("eth0 MTU = %q, want mtu=eth0=1500\n%s", line, output)
	}
	if line := findLine(output, "loopback="); line != "loopback=up" {
		t.Fatalf("loopback state = %q, want up\n%s", line, output)
	}
	if line := findLine(output, "default-route="); line != "default-route="+gateway {
		t.Fatalf("default route = %q, want %s\n%s", line, "default-route="+gateway, output)
	}
	if line := findLine(output, "ipv6="); line != "ipv6=none" {
		t.Fatalf("IPv6 state = %q, want none\n%s", line, output)
	}
	identity := findLine(output, "uid=")
	if !strings.Contains(identity, "pid=2 ppid=1") {
		t.Fatalf("payload identity = %q, want namespace pid=2 and ppid=1\n%s", identity, output)
	}
}

func bridgePrerequisiteUnavailable(err error) bool {
	message := err.Error()
	for _, marker := range []string{
		"CAP_NET_ADMIN",
		"trusted ip:",
		"trusted iptables:",
	} {
		if strings.Contains(message, marker) {
			return true
		}
	}
	return false
}

func skipBridgeUnavailable(t *testing.T, reason string) {
	t.Helper()
	fmt.Fprintln(os.Stderr, bridgeUnavailablePrefix+reason)
	skipOrFail(t, reason)
}

func bridgeUnavailableReason(output string) (string, bool) {
	for _, line := range strings.Split(output, "\n") {
		if index := strings.Index(line, bridgeUnavailablePrefix); index >= 0 {
			reason := strings.TrimSpace(line[index+len(bridgeUnavailablePrefix):])
			if reason != "" {
				return reason, true
			}
		}
	}
	return "", false
}

func TestBridgeUnavailableReason(t *testing.T) {
	for _, tc := range []struct {
		name   string
		output string
		want   string
		found  bool
	}{
		{name: "marker", output: bridgeUnavailablePrefix + "forwarding is read-only", want: "forwarding is read-only", found: true},
		{name: "none", output: "PASS\nordinary output\n", found: false},
		{name: "runner output", output: "=== RUN   TestSandboxPrivilegedBridgeLifecycle\n" + bridgeUnavailablePrefix + "missing CAP_NET_ADMIN\n--- SKIP: TestSandboxPrivilegedBridgeLifecycle\nPASS\n", want: "missing CAP_NET_ADMIN", found: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, found := bridgeUnavailableReason(tc.output)
			if got != tc.want || found != tc.found {
				t.Fatalf("bridgeUnavailableReason() = %q, %v; want %q, %v", got, found, tc.want, tc.found)
			}
		})
	}
}

func normalizeFirewallSnapshot(data []byte) []byte {
	var lines []string
	for _, line := range strings.Split(string(data), "\n") {
		if start := strings.IndexByte(line, '['); start >= 0 {
			if end := strings.IndexByte(line[start:], ']'); end >= 0 {
				line = line[:start] + line[start+end+1:]
			}
		}
		lines = append(lines, line)
	}
	return []byte(strings.Join(lines, "\n"))
}

func trustedBridgeTool(t *testing.T, name string) string {
	t.Helper()
	for _, dir := range []string{"/usr/sbin", "/usr/bin", "/sbin", "/bin"} {
		path := filepath.Join(dir, name)
		if info, err := os.Stat(path); err == nil && info.Mode().IsRegular() && info.Mode()&0111 != 0 {
			return path
		}
	}
	skipBridgeUnavailable(t, "trusted "+name+" is unavailable")
	return ""
}

func bridgeCommandOutput(t *testing.T, name string, args ...string) []byte {
	t.Helper()
	return bridgeCommandOutputPath(t, trustedBridgeTool(t, name), args...)
}

func bridgeCommandOutputPath(t *testing.T, path string, args ...string) []byte {
	t.Helper()
	output, err := exec.Command(path, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("%s %v failed: %v\n%s", path, args, err, output)
	}
	return output
}
