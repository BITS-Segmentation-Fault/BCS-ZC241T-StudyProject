package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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
		if err := exec.Command("unshare", "-Urn", "true").Run(); err != nil {
			skipOrFail(t, fmt.Sprintf("isolated bridge namespace is unavailable: %v", err))
		}
		command := exec.Command("unshare", "-Urn", os.Args[0], "-test.run=TestSandboxPrivilegedBridgeLifecycle", "-test.v")
		command.Env = withEnvironment(os.Environ(), "SANDBOX_BRIDGE_E2E_INNER", "1")
		output, err := command.CombinedOutput()
		if reason, ok := bridgeUnavailableReason(string(output)); ok {
			skipOrFail(t, reason)
		}
		if err != nil {
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
	routesBefore := bridgeCommandOutput(t, "ip", "-j", "-4", "route", "show", "table", "all")
	firewallSave := trustedBridgeTool(t, "iptables-save")
	firewallBefore := normalizeFirewallSnapshot(bridgeCommandOutputPath(t, firewallSave))
	first := newSandboxConfig(rootfs, "bridge", "/bin/probe", "inspect", "10s")
	firstConfig := writeSandboxConfig(t, first)
	firstCommand := exec.Command(sandbox, "--config", firstConfig)
	firstStdout, err := firstCommand.StdoutPipe()
	if err != nil {
		t.Fatalf("create first bridge stdout pipe: %v", err)
	}
	var firstStderr bytes.Buffer
	firstCommand.Stderr = &firstStderr
	if err := firstCommand.Start(); err != nil {
		t.Fatalf("start first bridge sandbox: %v", err)
	}
	firstCapture := captureBridgeProbe(firstStdout)
	second := newSandboxConfig(rootfs, "bridge", "/bin/probe", "inspect", "10s")
	second.BridgeConfig.Subnet = "10.0.101.0/24"
	second.BridgeConfig.GatewayIP = "10.0.101.1"
	second.BridgeConfig.ContainerIP = "10.0.101.2"
	secondConfig := writeSandboxConfig(t, second)
	secondCommand := exec.Command(sandbox, "--config", secondConfig)
	secondStdout, err := secondCommand.StdoutPipe()
	if err != nil {
		_ = firstCommand.Process.Kill()
		_ = firstCommand.Wait()
		t.Fatalf("create second bridge stdout pipe: %v", err)
	}
	var secondStderr bytes.Buffer
	secondCommand.Stderr = &secondStderr
	if err := secondCommand.Start(); err != nil {
		_ = firstCommand.Process.Kill()
		_ = firstCommand.Wait()
		t.Fatalf("start second bridge sandbox: %v", err)
	}
	secondCapture := captureBridgeProbe(secondStdout)
	var firstWaited, secondWaited bool
	cleanup := func() {
		if firstCommand.Process != nil && !firstWaited {
			_ = firstCommand.Process.Kill()
			_ = firstCommand.Wait()
			firstWaited = true
		}
		if secondCommand.Process != nil && !secondWaited {
			_ = secondCommand.Process.Kill()
			_ = secondCommand.Wait()
			secondWaited = true
		}
	}
	t.Cleanup(func() {
		cleanup()
	})
	if err := firstCapture.waitReady(); err != nil {
		cleanup()
		t.Fatalf("first bridge probe did not reach readiness: %v\nstdout=%s\nstderr=%s", err, firstCapture.output(), firstStderr.String())
	}
	if err := secondCapture.waitReady(); err != nil {
		cleanup()
		t.Fatalf("second bridge probe did not reach readiness: %v\nstdout=%s\nstderr=%s", err, secondCapture.output(), secondStderr.String())
	}
	expectations := []bridgeFirewallExpectation{
		{subnet: "10.0.100.0/24"},
		{subnet: "10.0.101.0/24"},
	}
	if err := waitForBridgeRules(firewallSave, expectations); err != nil {
		cleanup()
		t.Fatalf("bridge firewall rules were not installed: %v\nfirst stdout=%s\nsecond stdout=%s\nfirst stderr=%s\nsecond stderr=%s", err, firstCapture.output(), secondCapture.output(), firstStderr.String(), secondStderr.String())
	}
	linkNames := parseLinkNames(bridgeCommandOutput(t, "ip", "-o", "link", "show"))
	var bridges []string
	for _, name := range linkNames {
		if strings.HasPrefix(name, "sb") {
			bridges = append(bridges, name)
		}
	}
	if len(bridges) != 2 {
		cleanup()
		t.Fatalf("bridge links = %v, want two owned bridges", bridges)
	}
	routesDuring := bridgeCommandOutput(t, "ip", "-j", "-4", "route", "show", "table", "all")
	assertBridgeRoutes(t, routesDuring, bridges, map[string]string{
		"10.0.100.0/24": "10.0.100.1",
		"10.0.101.0/24": "10.0.101.1",
	})
	_ = firstCommand.Process.Signal(os.Interrupt)
	_ = secondCommand.Process.Signal(os.Interrupt)
	firstErr := firstCommand.Wait()
	firstWaited = true
	secondErr := secondCommand.Wait()
	secondWaited = true
	requireBridgeExitStatus(t, "first signalled sandbox", firstErr, 128+int(syscall.SIGINT), firstCapture.output(), firstStderr.String())
	requireBridgeExitStatus(t, "second signalled sandbox", secondErr, 128+int(syscall.SIGINT), secondCapture.output(), secondStderr.String())
	assertNoBridgeCleanupDiagnostic(t, "first signalled sandbox", firstStderr.String())
	assertNoBridgeCleanupDiagnostic(t, "second signalled sandbox", secondStderr.String())
	assertBridgePayload(t, firstCapture.output(), "10.0.100.2/24", "10.0.100.1")
	assertBridgePayload(t, secondCapture.output(), "10.0.101.2/24", "10.0.101.1")
	linksAfter := bridgeCommandOutput(t, "ip", "-o", "link", "show")
	if string(linksBefore) != string(linksAfter) {
		t.Fatalf("host links changed across bridge lifecycle:\nbefore=%safter=%s", linksBefore, linksAfter)
	}
	routesAfter := bridgeCommandOutput(t, "ip", "-j", "-4", "route", "show", "table", "all")
	assertNoBridgeRoutes(t, routesAfter, map[string]string{
		"10.0.100.0/24": "10.0.100.1",
		"10.0.101.0/24": "10.0.101.1",
	})
	if string(routesBefore) == string(routesDuring) {
		t.Fatalf("bridge routes did not appear during setup")
	}
	firewallAfter := normalizeFirewallSnapshot(bridgeCommandOutputPath(t, firewallSave))
	if strings.Contains(string(firewallAfter), "study-project-sandbox") || string(firewallBefore) != string(firewallAfter) {
		t.Fatalf("owned firewall state was not cleaned up\nbefore=%q after=%q", firewallBefore, firewallAfter)
	}

	normal := newSandboxConfig(rootfs, "bridge", "/bin/probe", "exit", "0")
	normalCommand := exec.Command(sandbox, "--config", writeSandboxConfig(t, normal))
	var normalStdout, normalStderr bytes.Buffer
	normalCommand.Stdout = &normalStdout
	normalCommand.Stderr = &normalStderr
	if err := normalCommand.Run(); err != nil {
		t.Fatalf("normally exiting bridge sandbox failed: %v\nstdout=%s\nstderr=%s", err, normalStdout.String(), normalStderr.String())
	}
	assertNoBridgeCleanupDiagnostic(t, "normally exiting sandbox", normalStderr.String())
	linksAfterNormal := bridgeCommandOutput(t, "ip", "-o", "link", "show")
	if string(linksBefore) != string(linksAfterNormal) {
		t.Fatalf("host links changed after normal bridge lifecycle:\nbefore=%safter=%s", linksBefore, linksAfterNormal)
	}
	routesAfterNormal := bridgeCommandOutput(t, "ip", "-j", "-4", "route", "show", "table", "all")
	assertNoBridgeRoutes(t, routesAfterNormal, map[string]string{
		"10.0.100.0/24": "10.0.100.1",
		"10.0.101.0/24": "10.0.101.1",
	})
	firewallAfterNormal := normalizeFirewallSnapshot(bridgeCommandOutputPath(t, firewallSave))
	if strings.Contains(string(firewallAfterNormal), "study-project-sandbox") || string(firewallBefore) != string(firewallAfterNormal) {
		t.Fatalf("owned firewall state remained after normal lifecycle\nbefore=%q after=%q", firewallBefore, firewallAfterNormal)
	}
}

type bridgeFirewallExpectation struct {
	subnet string
}

type bridgeRoute struct {
	Destination string `json:"dst"`
	Device      string `json:"dev"`
	Protocol    string `json:"protocol"`
	Source      string `json:"prefsrc"`
}

func assertBridgeRoutes(t *testing.T, data []byte, bridges []string, expected map[string]string) {
	t.Helper()
	var routes []bridgeRoute
	if err := json.Unmarshal(data, &routes); err != nil {
		t.Fatalf("decode bridge routes: %v", err)
	}
	owned := make(map[string]bool, len(bridges))
	for _, bridge := range bridges {
		owned[bridge] = true
	}
	for subnet, gateway := range expected {
		found := false
		for _, route := range routes {
			if route.Destination == subnet && owned[route.Device] && route.Protocol == "static" && route.Source == gateway {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("route %s via %s was not installed on an owned bridge: %s", subnet, gateway, data)
		}
	}
}

func assertNoBridgeRoutes(t *testing.T, data []byte, expected map[string]string) {
	t.Helper()
	var routes []bridgeRoute
	if err := json.Unmarshal(data, &routes); err != nil {
		t.Fatalf("decode final bridge routes: %v", err)
	}
	for _, route := range routes {
		if _, ok := expected[route.Destination]; ok && strings.HasPrefix(route.Device, "sb") {
			t.Fatalf("owned bridge route remained after teardown: %s", data)
		}
	}
}

func requireBridgeExitStatus(t *testing.T, name string, err error, want int, stdout, stderr string) {
	t.Helper()
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != want {
		t.Fatalf("%s status = %v, want %d\nstdout=%s\nstderr=%s", name, err, want, stdout, stderr)
	}
}

func assertNoBridgeCleanupDiagnostic(t *testing.T, name, stderr string) {
	t.Helper()
	if strings.Contains(strings.ToLower(stderr), "bridge cleanup") {
		t.Fatalf("%s reported bridge cleanup failure: %s", name, stderr)
	}
}

type bridgeProbeResult struct {
	output string
	ready  bool
	err    error
}

type bridgeProbeCapture struct {
	ready  chan struct{}
	done   chan bridgeProbeResult
	result *bridgeProbeResult
}

func captureBridgeProbe(stdout io.ReadCloser) *bridgeProbeCapture {
	capture := &bridgeProbeCapture{
		ready: make(chan struct{}),
		done:  make(chan bridgeProbeResult, 1),
	}
	go func() {
		var output bytes.Buffer
		reader := bufio.NewReader(stdout)
		ready := false
		var readErr error
		for {
			line, err := reader.ReadString('\n')
			if line != "" {
				output.WriteString(line)
				if line == "ready\n" && !ready {
					ready = true
					close(capture.ready)
				}
			}
			if err != nil {
				if err != io.EOF {
					readErr = err
				}
				break
			}
		}
		if !ready && readErr == nil {
			readErr = errors.New("stdout closed before ready")
		}
		capture.done <- bridgeProbeResult{output: output.String(), ready: ready, err: readErr}
	}()
	return capture
}

func (capture *bridgeProbeCapture) waitReady() error {
	select {
	case <-capture.ready:
		return nil
	case result := <-capture.done:
		capture.result = &result
		if result.ready {
			return nil
		}
		return result.err
	}
}

func (capture *bridgeProbeCapture) output() string {
	if capture.result == nil {
		result := <-capture.done
		capture.result = &result
	}
	return capture.result.output
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

type parsedFirewallRule struct {
	table           string
	chain           string
	inputInterface  string
	outputInterface string
	source          string
	destination     string
	comment         string
	connectionState map[string]bool
	jump            string
	rejectWith      string
	outputNegated   bool
	invalid         bool
}

func firewallRuleLines(data []byte) []parsedFirewallRule {
	var rules []parsedFirewallRule
	table := ""
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 1 && strings.HasPrefix(fields[0], "*") {
			table = strings.TrimPrefix(fields[0], "*")
			continue
		}
		if len(fields) < 2 || fields[0] != "-A" {
			continue
		}
		rule := parsedFirewallRule{table: table, chain: fields[1], connectionState: make(map[string]bool)}
		negated := false
		seen := make(map[string]bool)
		markSeen := func(attribute string) bool {
			if seen[attribute] {
				rule.invalid = true
				return false
			}
			seen[attribute] = true
			return true
		}
		for index := 2; index < len(fields); index++ {
			switch fields[index] {
			case "!":
				if negated {
					rule.invalid = true
				}
				negated = true
			case "-i", "--in-interface":
				if index+1 >= len(fields) || negated || !markSeen("input-interface") {
					rule.invalid = true
					continue
				}
				rule.inputInterface = fields[index+1]
				index++
			case "-o", "--out-interface":
				if index+1 >= len(fields) || !markSeen("output-interface") {
					rule.invalid = true
					continue
				}
				rule.outputInterface = fields[index+1]
				rule.outputNegated = negated
				negated = false
				index++
			case "-s", "--source":
				if index+1 >= len(fields) || negated || !markSeen("source") {
					rule.invalid = true
					continue
				}
				rule.source = fields[index+1]
				index++
			case "-d", "--destination":
				if index+1 >= len(fields) || negated || !markSeen("destination") {
					rule.invalid = true
					continue
				}
				rule.destination = fields[index+1]
				index++
			case "-m":
				if index+1 >= len(fields) || (fields[index+1] != "comment" && fields[index+1] != "conntrack" && fields[index+1] != "state") || negated {
					rule.invalid = true
					continue
				}
				index++
			case "--comment":
				if index+1 >= len(fields) || negated || !markSeen("comment") {
					rule.invalid = true
					continue
				}
				rule.comment = fields[index+1]
				index++
			case "--ctstate", "--state":
				if index+1 >= len(fields) || negated || !markSeen("connection-state") {
					rule.invalid = true
					continue
				}
				for _, state := range strings.Split(fields[index+1], ",") {
					if state == "" {
						rule.invalid = true
						continue
					}
					rule.connectionState[strings.ToUpper(state)] = true
				}
				index++
			case "-j", "--jump":
				if index+1 >= len(fields) || negated || !markSeen("jump") {
					rule.invalid = true
					continue
				}
				rule.jump = fields[index+1]
				index++
			case "--reject-with":
				if index+1 >= len(fields) || negated || !markSeen("reject-with") {
					rule.invalid = true
					continue
				}
				rule.rejectWith = fields[index+1]
				index++
			default:
				rule.invalid = true
			}
		}
		if negated {
			rule.invalid = true
		}
		rules = append(rules, rule)
	}
	return rules
}

func findBridgeFirewallIdentity(rules []parsedFirewallRule, subnet string) (string, string, bool) {
	for _, rule := range rules {
		want := parsedFirewallRule{
			table:           "nat",
			chain:           "POSTROUTING",
			outputInterface: rule.outputInterface,
			source:          subnet,
			comment:         rule.comment,
			jump:            "MASQUERADE",
			outputNegated:   true,
			connectionState: make(map[string]bool),
		}
		if rule.comment != "" && firewallRuleMatches(rule, want) {
			return rule.outputInterface, rule.comment, true
		}
	}
	return "", "", false
}

func expectedBridgeFirewallRules(bridge, subnet, label string) []parsedFirewallRule {
	return []parsedFirewallRule{
		{table: "filter", chain: "FORWARD", inputInterface: bridge, comment: label, jump: "ACCEPT", connectionState: make(map[string]bool)},
		{table: "filter", chain: "FORWARD", outputInterface: bridge, comment: label, jump: "REJECT", connectionState: map[string]bool{"NEW": true}},
		{table: "filter", chain: "FORWARD", outputInterface: bridge, comment: label, jump: "ACCEPT", connectionState: map[string]bool{"ESTABLISHED": true, "RELATED": true}},
		{table: "filter", chain: "INPUT", inputInterface: bridge, comment: label, jump: "REJECT", connectionState: make(map[string]bool)},
		{table: "filter", chain: "FORWARD", inputInterface: bridge, destination: "169.254.0.0/16", comment: label, jump: "REJECT", connectionState: make(map[string]bool)},
		{table: "nat", chain: "POSTROUTING", outputInterface: bridge, outputNegated: true, source: subnet, comment: label, jump: "MASQUERADE", connectionState: make(map[string]bool)},
	}
}

func firewallRuleMatches(got, want parsedFirewallRule) bool {
	if got.invalid || got.table != want.table || got.chain != want.chain ||
		got.inputInterface != want.inputInterface || got.outputInterface != want.outputInterface ||
		got.source != want.source || got.destination != want.destination || got.comment != want.comment ||
		got.jump != want.jump || got.outputNegated != want.outputNegated ||
		!equalFirewallStateSets(got.connectionState, want.connectionState) {
		return false
	}
	if got.rejectWith != "" && (got.jump != "REJECT" || got.rejectWith != "icmp-port-unreachable") {
		return false
	}
	return true
}

func equalFirewallStateSets(left, right map[string]bool) bool {
	if len(left) != len(right) {
		return false
	}
	for state := range left {
		if !right[state] {
			return false
		}
	}
	return true
}

func hasFirewallRule(rules []parsedFirewallRule, want parsedFirewallRule) bool {
	for _, rule := range rules {
		if firewallRuleMatches(rule, want) {
			return true
		}
	}
	return false
}

func TestBridgeFirewallSemanticMatching(t *testing.T) {
	const (
		bridge = "sb0"
		subnet = "10.0.0.0/24"
		label  = "study-project-sandbox-test"
	)
	expectations := []bridgeFirewallExpectation{{subnet: subnet}}
	canonical := fmt.Sprintf(`*filter
:INPUT ACCEPT [0:0]
:FORWARD ACCEPT [0:0]
-A FORWARD -i %s -m comment --comment %s -j ACCEPT
-A FORWARD -o %s -m conntrack --ctstate NEW -m comment --comment %s -j REJECT
-A FORWARD -o %s -m conntrack --ctstate ESTABLISHED,RELATED -m comment --comment %s -j ACCEPT
-A INPUT -i %s -m comment --comment %s -j REJECT
-A FORWARD -i %s -d 169.254.0.0/16 -m comment --comment %s -j REJECT
COMMIT
*nat
:POSTROUTING ACCEPT [0:0]
-A POSTROUTING -s %s ! -o %s -m comment --comment %s -j MASQUERADE
COMMIT
`, bridge, label, bridge, label, bridge, label, bridge, label, bridge, label, subnet, bridge, label)
	fedora := fmt.Sprintf(`*filter
:INPUT ACCEPT [0:0]
:FORWARD ACCEPT [0:0]
-A FORWARD -m comment --comment %s -i %s -j ACCEPT
-A FORWARD -m comment --comment %s -o %s -m conntrack --ctstate NEW -j REJECT --reject-with icmp-port-unreachable
-A FORWARD -o %s -m comment --comment %s -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A INPUT -m comment --comment %s -i %s -j REJECT --reject-with icmp-port-unreachable
-A FORWARD -d 169.254.0.0/16 -i %s -m comment --comment %s -j REJECT --reject-with icmp-port-unreachable
COMMIT
*nat
:POSTROUTING ACCEPT [0:0]
-A POSTROUTING -s %s ! -o %s -m comment --comment %s -j MASQUERADE
COMMIT
`, label, bridge, label, bridge, bridge, label, label, bridge, bridge, label, subnet, bridge, label)
	cases := []struct {
		name  string
		data  string
		links []string
		want  bool
	}{
		{name: "canonical ordering", data: canonical, links: []string{bridge}, want: true},
		{name: "fedora nft ordering", data: fedora, links: []string{bridge}, want: true},
		{name: "missing rule", data: strings.Replace(canonical, fmt.Sprintf("-A INPUT -i %s -m comment --comment %s -j REJECT\n", bridge, label), "", 1), links: []string{bridge}, want: false},
		{name: "wrong interface", data: strings.Replace(canonical, "-A FORWARD -i sb0 -m comment", "-A FORWARD -i sb9 -m comment", 1), links: []string{bridge}, want: false},
		{name: "wrong subnet", data: strings.Replace(canonical, "-s 10.0.0.0/24", "-s 10.0.1.0/24", 1), links: []string{bridge}, want: false},
		{name: "missing negation", data: strings.Replace(canonical, "! -o sb0", "-o sb0", 1), links: []string{bridge}, want: false},
		{name: "incorrect state", data: strings.Replace(canonical, "--ctstate NEW", "--ctstate ESTABLISHED", 1), links: []string{bridge}, want: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := bridgeFirewallPoliciesPresent([]byte(tc.data), tc.links, expectations); got != tc.want {
				t.Fatalf("bridgeFirewallPoliciesPresent() = %v, want %v", got, tc.want)
			}
		})
	}
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
	requireSupervisedPayloadIdentity(t, output, "/work")
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
	var table []string
	insideTable := false
	tableHasRule := false
	flushTable := func() {
		if insideTable && tableHasRule {
			lines = append(lines, table...)
		}
		table = nil
		insideTable = false
		tableHasRule = false
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "# Generated by ") || strings.HasPrefix(line, "# Completed on ") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 1 && strings.HasPrefix(fields[0], "*") {
			flushTable()
			insideTable = true
			table = append(table, line)
			continue
		}
		if start := strings.IndexByte(line, '['); start >= 0 {
			if end := strings.IndexByte(line[start:], ']'); end >= 0 {
				line = line[:start] + line[start+end+1:]
			}
		}
		if insideTable {
			table = append(table, line)
			if len(fields) > 0 && fields[0] == "-A" {
				tableHasRule = true
			}
			if line == "COMMIT" {
				flushTable()
			}
		} else {
			lines = append(lines, line)
		}
	}
	flushTable()
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
