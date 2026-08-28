//go:build linux

package network

import (
	"errors"
	"net/netip"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"
)

type mockNetlinkOps struct {
	ops             []string
	fail            string
	failPrefix      string
	interfaces      []string
	links           map[string]bool
	vethPeers       map[string]string
	inspectErr      error
	removeOnFailure map[string]bool
}

func (m *mockNetlinkOps) record(operation string) error {
	m.ops = append(m.ops, operation)
	if m.fail == operation || (m.failPrefix != "" && strings.HasPrefix(operation, m.failPrefix)) {
		return errors.New("simulated failure")
	}
	return nil
}
func (m *mockNetlinkOps) BridgeAdd(name string) error {
	err := m.record("BridgeAdd " + name)
	if err == nil {
		m.addLink(name)
	}
	return err
}
func (m *mockNetlinkOps) BridgeDel(name string) error {
	err := m.record("BridgeDel " + name)
	if err == nil && !m.links[name] {
		err = errors.New("link is absent")
	}
	if err == nil || m.removeAfterFailure(name) {
		m.removeLink(name)
	}
	return err
}
func (m *mockNetlinkOps) VethCreate(name, peer string) error {
	err := m.record("VethCreate " + name + " " + peer)
	if err == nil {
		m.addLink(name)
		m.addLink(peer)
		if m.vethPeers == nil {
			m.vethPeers = make(map[string]string)
		}
		m.vethPeers[name] = peer
		m.vethPeers[peer] = name
	}
	return err
}
func (m *mockNetlinkOps) VethDelete(name string) error {
	err := m.record("VethDelete " + name)
	if err == nil && !m.links[name] {
		err = errors.New("link is absent")
	}
	if err == nil || m.removeAfterFailure(name) {
		m.removeVethPair(name)
	}
	return err
}
func (m *mockNetlinkOps) LinkSetMaster(link, master string) error {
	return m.record("LinkSetMaster " + link + " " + master)
}
func (m *mockNetlinkOps) LinkSetUp(name string) error { return m.record("LinkSetUp " + name) }
func (m *mockNetlinkOps) LinkSetMTU(name string, mtu int) error {
	return m.record("LinkSetMTU " + name)
}
func (m *mockNetlinkOps) LinkSetMAC(name string, _ []byte) error {
	return m.record("LinkSetMAC " + name)
}
func (m *mockNetlinkOps) LinkSetName(oldName, newName string) error {
	return m.record("LinkSetName " + oldName + " " + newName)
}
func (m *mockNetlinkOps) AddrAdd(iface, ip string) error {
	return m.record("AddrAdd " + iface + " " + ip)
}
func (m *mockNetlinkOps) LinkNames() ([]string, error) {
	if m.inspectErr != nil {
		return nil, m.inspectErr
	}
	if m.links == nil {
		return append([]string(nil), m.interfaces...), nil
	}
	result := make([]string, 0, len(m.links))
	for name := range m.links {
		result = append(result, name)
	}
	sort.Strings(result)
	return result, nil
}
func (m *mockNetlinkOps) DisableIPv6() error {
	return m.record("DisableIPv6")
}

func (m *mockNetlinkOps) addLink(name string) {
	if m.links == nil {
		m.links = make(map[string]bool)
	}
	m.links[name] = true
}

func (m *mockNetlinkOps) removeLink(name string) {
	delete(m.links, name)
}

func (m *mockNetlinkOps) removeVethPair(name string) {
	peer := m.vethPeers[name]
	m.removeLink(name)
	m.removeLink(peer)
	delete(m.vethPeers, name)
	delete(m.vethPeers, peer)
}

func (m *mockNetlinkOps) removeAfterFailure(name string) bool {
	return m.removeOnFailure != nil && m.removeOnFailure[name]
}

type mockFirewallOps struct {
	adds       [][]string
	deletes    [][]string
	failAt     int
	deleteFail bool
}

func (m *mockFirewallOps) Add(rule []string) error {
	m.adds = append(m.adds, append([]string(nil), rule...))
	if m.failAt > 0 && len(m.adds) == m.failAt {
		return errors.New("firewall failure")
	}
	return nil
}
func (m *mockFirewallOps) Delete(rule []string) error {
	m.deletes = append(m.deletes, append([]string(nil), rule...))
	if m.deleteFail {
		return errors.New("firewall delete failure")
	}
	return nil
}

func testBridgeConfig() BridgeConfig { return DefaultBridgeConfig() }

func mustPrefix(value string) netip.Prefix {
	prefix, err := netip.ParsePrefix(value)
	if err != nil {
		panic(err)
	}
	return prefix
}

func testOperations(mock *mockNetlinkOps) operations {
	return operations{
		netlink:   mock,
		runIP:     testRunIP(mock),
		routeList: mockRouteList(mock, nil),
		firewall:  &mockFirewallOps{},
	}
}

func testRunIP(mock *mockNetlinkOps) func(...string) error {
	return func(args ...string) error { return mock.record("IP " + strings.Join(args, " ")) }
}

func mockRouteList(mock *mockNetlinkOps, preflight []routeInfo) func() ([]routeInfo, error) {
	calls := 0
	return func() ([]routeInfo, error) {
		calls++
		if calls == 1 {
			return preflight, nil
		}
		for _, operation := range mock.ops {
			fields := strings.Fields(operation)
			if len(fields) >= 6 && fields[0] == "IP" && fields[1] == "route" && fields[2] == "add" {
				prefix, _ := netip.ParsePrefix(fields[3])
				return []routeInfo{{prefix: prefix, device: fields[5]}}, nil
			}
		}
		return nil, nil
	}
}

func TestSetupParentBridgeProvisionsAddressAndRouteAfterLinksAreUp(t *testing.T) {
	mock := &mockNetlinkOps{}
	state, err := setupParentBridgeWithOps(testBridgeConfig(), testOperations(mock))
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := state.cleanup(); err != nil {
			t.Fatal(err)
		}
	}()

	address := "IP addr add 10.0.100.1/24 dev " + state.bridge + " noprefixroute"
	route := "IP route add 10.0.100.0/24 dev " + state.bridge + " src 10.0.100.1 proto static"
	if !containsOperation(mock.ops, address) || !containsOperation(mock.ops, route) {
		t.Fatalf("operations = %v", mock.ops)
	}
	if operationIndex(mock.ops, "LinkSetUp "+state.hostVeth) > operationIndex(mock.ops, address) || operationIndex(mock.ops, "LinkSetUp "+state.bridge) > operationIndex(mock.ops, address) {
		t.Fatalf("address was provisioned before links were up: %v", mock.ops)
	}
	if operationIndex(mock.ops, address) > operationIndex(mock.ops, route) {
		t.Fatalf("route was provisioned before address: %v", mock.ops)
	}
}

func TestBridgeRouteFailureRollsBackOwnedLinks(t *testing.T) {
	mock := &mockNetlinkOps{failPrefix: "IP route add "}
	state, err := setupParentBridgeWithOps(testBridgeConfig(), testOperations(mock))
	if err == nil || state != nil {
		t.Fatalf("route failure was accepted: state=%v err=%v", state, err)
	}
	if !containsOperationPrefix(mock.ops, "VethDelete ") || !containsOperationPrefix(mock.ops, "BridgeDel ") {
		t.Fatalf("route failure did not roll back links: %v", mock.ops)
	}
}

func TestMissingBridgeRouteAfterExplicitAddRollsBack(t *testing.T) {
	mock := &mockNetlinkOps{}
	calls := 0
	ops := testOperations(mock)
	ops.routeList = func() ([]routeInfo, error) {
		calls++
		if calls == 1 {
			return nil, nil
		}
		return nil, nil
	}
	state, err := setupParentBridgeWithOps(testBridgeConfig(), ops)
	if err == nil || state != nil {
		t.Fatalf("missing route was accepted: state=%v err=%v", state, err)
	}
	if !containsOperationPrefix(mock.ops, "VethDelete ") || !containsOperationPrefix(mock.ops, "BridgeDel ") {
		t.Fatalf("missing route did not roll back links: %v", mock.ops)
	}
}

func TestSetupParentBridgeRollsBackOwnedResources(t *testing.T) {
	mock := &mockNetlinkOps{}
	state, err := setupParentBridgeWithOps(testBridgeConfig(), testOperations(mock))
	if err != nil {
		t.Fatal(err)
	}
	if err := state.cleanup(); err != nil {
		t.Fatal(err)
	}
	if len(mock.ops) == 0 || !strings.HasPrefix(mock.ops[0], "BridgeAdd ") {
		t.Fatalf("operations = %v", mock.ops)
	}
}

func TestChildInterfaceDiscovery(t *testing.T) {
	mock := &mockNetlinkOps{interfaces: []string{"lo", "veth0"}}
	manager := newBridgeManager(testOperations(mock))
	if err := manager.configureChildIface(testBridgeConfig()); err != nil {
		t.Fatal(err)
	}
	if !containsOperation(mock.ops, "LinkSetName veth0 eth0") {
		t.Fatalf("operations = %v", mock.ops)
	}
	if !containsOperation(mock.ops, "DisableIPv6") {
		t.Fatalf("operations = %v", mock.ops)
	}
	for _, interfaces := range [][]string{{"lo"}, {"lo", "a", "b"}} {
		mock.interfaces = interfaces
		if err := manager.configureChildIface(testBridgeConfig()); err == nil {
			t.Fatalf("interfaces %v were accepted", interfaces)
		}
	}
}

func TestRealNetlinkOpsDisableIPv6(t *testing.T) {
	var writes []string
	ops := &realNetlinkOps{writeFile: func(path string, data []byte, _ os.FileMode) error {
		writes = append(writes, path+":"+string(data))
		return nil
	}}
	if err := ops.DisableIPv6(); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"/proc/sys/net/ipv6/conf/all/disable_ipv6:1\n",
		"/proc/sys/net/ipv6/conf/default/disable_ipv6:1\n",
	}
	if !reflect.DeepEqual(writes, want) {
		t.Fatalf("IPv6 writes = %v, want %v", writes, want)
	}
}

func TestGeneratedNamesArePrivateAndUnique(t *testing.T) {
	a := DefaultBridgeConfig()
	b := DefaultBridgeConfig()
	if !reflect.DeepEqual(a, b) {
		t.Fatalf("defaults changed between calls: %#v %#v", a, b)
	}
	firstParts := []string{"\x00"}
	firstParts[0] = string([]byte{1, 2, 3, 4, 5, 6})
	secondParts := []byte{6, 5, 4, 3, 2, 1}
	a1, b1, c1, err := resourceNames(strings.NewReader(firstParts[0]))
	if err != nil {
		t.Fatal(err)
	}
	a2, b2, c2, err := resourceNames(strings.NewReader(string(secondParts)))
	if err != nil {
		t.Fatal(err)
	}
	first := strings.Join([]string{a1, b1, c1}, "/")
	second := strings.Join([]string{a2, b2, c2}, "/")
	if first == second {
		t.Fatalf("resource names are not unique: %v", first)
	}
}

func TestResourceNamesRejectEntropyFailure(t *testing.T) {
	if _, _, _, err := resourceNames(strings.NewReader("short")); err == nil {
		t.Fatal("short entropy input was accepted")
	}
}

func TestProductionOperationsInspectRoutes(t *testing.T) {
	if newBridgeManager(operations{}).ops.routeList == nil {
		t.Fatal("production bridge operations have no route inspection")
	}
}

func TestRoutePrefixesRejectsUnrecognizedOutput(t *testing.T) {
	path := t.TempDir() + "/ip"
	if err := os.WriteFile(path, []byte("#!/bin/sh\nprintf 'not route json\\n'\n"), 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := routePrefixes(path); err == nil {
		t.Fatal("unrecognized route output was accepted")
	}
}

func TestFirewallRulesDenyBeforeAllow(t *testing.T) {
	want := []firewallRule{
		{add: []string{"-I", "FORWARD", "1", "-i", "sb0", "-m", "comment", "--comment", "run", "-j", "ACCEPT"}, del: []string{"-D", "FORWARD", "-i", "sb0", "-m", "comment", "--comment", "run", "-j", "ACCEPT"}},
		{add: []string{"-I", "FORWARD", "1", "-o", "sb0", "-m", "conntrack", "--ctstate", "NEW", "-m", "comment", "--comment", "run", "-j", "REJECT"}, del: []string{"-D", "FORWARD", "-o", "sb0", "-m", "conntrack", "--ctstate", "NEW", "-m", "comment", "--comment", "run", "-j", "REJECT"}},
		{add: []string{"-I", "FORWARD", "1", "-o", "sb0", "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-m", "comment", "--comment", "run", "-j", "ACCEPT"}, del: []string{"-D", "FORWARD", "-o", "sb0", "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-m", "comment", "--comment", "run", "-j", "ACCEPT"}},
		{add: []string{"-I", "INPUT", "1", "-i", "sb0", "-m", "comment", "--comment", "run", "-j", "REJECT"}, del: []string{"-D", "INPUT", "-i", "sb0", "-m", "comment", "--comment", "run", "-j", "REJECT"}},
		{add: []string{"-I", "FORWARD", "1", "-i", "sb0", "-d", "169.254.0.0/16", "-m", "comment", "--comment", "run", "-j", "REJECT"}, del: []string{"-D", "FORWARD", "-i", "sb0", "-d", "169.254.0.0/16", "-m", "comment", "--comment", "run", "-j", "REJECT"}},
		{add: []string{"-t", "nat", "-I", "POSTROUTING", "1", "-s", "10.0.0.0/24", "!", "-o", "sb0", "-m", "comment", "--comment", "run", "-j", "MASQUERADE"}, del: []string{"-t", "nat", "-D", "POSTROUTING", "-s", "10.0.0.0/24", "!", "-o", "sb0", "-m", "comment", "--comment", "run", "-j", "MASQUERADE"}},
	}
	if rules := firewallRules("10.0.0.0/24", "sb0", "run"); !reflect.DeepEqual(rules, want) {
		t.Fatalf("firewall rules = %#v, want %#v", rules, want)
	}
}

func TestFirewallSetupRollsBackReverseOrder(t *testing.T) {
	mock := &mockNetlinkOps{}
	firewall := &mockFirewallOps{failAt: 3}
	ops := operations{netlink: mock, runIP: testRunIP(mock), routeList: mockRouteList(mock, nil), firewall: firewall}
	state, err := setupParentBridgeWithOps(testBridgeConfig(), ops)
	if err != nil {
		t.Fatal(err)
	}
	if err := SetupFirewallForBridge(state); err == nil {
		t.Fatal("firewall setup unexpectedly succeeded")
	}
	if len(firewall.deletes) != 2 {
		t.Fatalf("rollback deleted %d rules, want 2", len(firewall.deletes))
	}
	if !sameRule(firewall.deletes[0], firewall.adds[1]) || !sameRule(firewall.deletes[1], firewall.adds[0]) {
		t.Fatalf("rollback order = %v, adds = %v", firewall.deletes, firewall.adds)
	}
}

func TestFirewallRollbackRetainsFailedRulesForRetry(t *testing.T) {
	mock := &mockNetlinkOps{}
	firewall := &mockFirewallOps{failAt: 3, deleteFail: true}
	ops := operations{netlink: mock, runIP: testRunIP(mock), routeList: mockRouteList(mock, nil), firewall: firewall}
	state, err := setupParentBridgeWithOps(testBridgeConfig(), ops)
	if err != nil {
		t.Fatal(err)
	}
	if err := SetupFirewallForBridge(state); err == nil {
		t.Fatal("firewall setup unexpectedly succeeded")
	}
	if len(state.firewall) != 2 {
		t.Fatalf("retained firewall rules = %d, want 2", len(state.firewall))
	}
	firewall.deleteFail = false
	if err := TeardownParentBridge(state); err != nil {
		t.Fatal(err)
	}
	if len(state.firewall) != 0 {
		t.Fatalf("firewall rules remain after retry: %v", state.firewall)
	}
}

func TestFirewallSetupCannotRunTwice(t *testing.T) {
	mock := &mockNetlinkOps{}
	state, err := setupParentBridgeWithOps(testBridgeConfig(), testOperations(mock))
	if err != nil {
		t.Fatal(err)
	}
	if err := SetupFirewallForBridge(state); err != nil {
		t.Fatal(err)
	}
	if err := SetupFirewallForBridge(state); err == nil {
		t.Fatal("firewall setup succeeded twice")
	}
	if err := TeardownParentBridge(state); err != nil {
		t.Fatal(err)
	}
}

func TestFirewallSetupAndTeardownAreSerialized(t *testing.T) {
	mock := &mockNetlinkOps{}
	firewall := &mockFirewallOps{}
	state, err := setupParentBridgeWithOps(testBridgeConfig(), operations{
		netlink:   mock,
		runIP:     testRunIP(mock),
		routeList: mockRouteList(mock, nil),
		firewall:  firewall,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := SetupFirewallForBridge(state); err != nil {
		t.Fatal(err)
	}
	setupDone := make(chan error, 1)
	go func() { setupDone <- SetupFirewallForBridge(state) }()
	cleanupDone := make(chan error, 1)
	go func() { cleanupDone <- TeardownParentBridge(state) }()
	if err := <-cleanupDone; err != nil {
		t.Fatal(err)
	}
	if err := <-setupDone; err == nil {
		t.Fatal("concurrent firewall setup succeeded after teardown")
	}
	if len(state.firewall) != 0 || state.ownedBridge || state.ownedVeth {
		t.Fatalf("teardown left owned state: firewall=%v bridge=%v veth=%v", state.firewall, state.ownedBridge, state.ownedVeth)
	}
}

func sameRule(del, add []string) bool {
	return len(del) >= 2 && len(add) >= 3 && strings.Join(del[2:], " ") == strings.Join(add[3:], " ")
}

func TestBridgePrerequisitesRequireCapabilityAndForwarding(t *testing.T) {
	oldCapability, oldResolver, oldRead := bridgeCapabilityCheck, bridgeToolResolver, bridgeReadFile
	t.Cleanup(func() {
		bridgeCapabilityCheck, bridgeToolResolver, bridgeReadFile = oldCapability, oldResolver, oldRead
	})
	bridgeCapabilityCheck = func() bool { return false }
	bridgeToolResolver = func(string) (string, error) { return "/trusted/tool", nil }
	bridgeReadFile = func(string) ([]byte, error) { return []byte("1\n"), nil }
	if err := CheckBridgePrerequisites(); err == nil || !strings.Contains(err.Error(), "CAP_NET_ADMIN") {
		t.Fatalf("capability check error = %v", err)
	}
	bridgeCapabilityCheck = func() bool { return true }
	bridgeReadFile = func(string) ([]byte, error) { return []byte("0\n"), nil }
	if err := CheckBridgePrerequisites(); err == nil || !strings.Contains(err.Error(), "forwarding") {
		t.Fatalf("forwarding check error = %v", err)
	}
}

func TestBridgeRejectsOverlappingRoutes(t *testing.T) {
	mock := &mockNetlinkOps{}
	ops := testOperations(mock)
	ops.routeList = func() ([]routeInfo, error) {
		prefix, _ := netip.ParsePrefix("10.0.0.0/8")
		return []routeInfo{{prefix: prefix, device: "other0"}}, nil
	}
	if state, err := setupParentBridgeWithOps(testBridgeConfig(), ops); err == nil || state != nil {
		t.Fatalf("overlapping route accepted: state=%v err=%v", state, err)
	}
	ops.routeList = mockRouteList(mock, []routeInfo{{prefix: mustPrefix("192.168.0.0/16"), device: "other0"}})
	state, err := setupParentBridgeWithOps(testBridgeConfig(), ops)
	if err != nil {
		t.Fatal(err)
	}
	if err := state.cleanup(); err != nil {
		t.Fatal(err)
	}
}

func TestBridgeRejectsPostAddressRouteOverlapAndRollsBack(t *testing.T) {
	for _, tc := range []struct {
		name   string
		prefix string
	}{
		{name: "identical", prefix: "10.0.100.0/24"},
		{name: "broader", prefix: "10.0.0.0/16"},
		{name: "narrower", prefix: "10.0.100.0/25"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mock := &mockNetlinkOps{}
			calls := 0
			ops := testOperations(mock)
			ops.routeList = func() ([]routeInfo, error) {
				calls++
				if calls == 1 {
					return nil, nil
				}
				prefix, _ := netip.ParsePrefix(tc.prefix)
				return []routeInfo{{prefix: prefix, device: "other0"}}, nil
			}
			state, err := setupParentBridgeWithOps(testBridgeConfig(), ops)
			if err == nil || state != nil {
				t.Fatalf("overlapping postcondition route accepted: state=%v err=%v", state, err)
			}
			if calls != 2 {
				t.Fatalf("route inspections = %d, want preflight and post-route", calls)
			}
			if countPrefix(mock.ops, "VethDelete ") == 0 || countPrefix(mock.ops, "BridgeDel ") == 0 {
				t.Fatalf("setup failure did not roll back links: %v", mock.ops)
			}
		})
	}
}

func TestBridgeCleanupRetriesOnlyFailedDeletes(t *testing.T) {
	mock := &mockNetlinkOps{}
	state, err := setupParentBridgeWithOps(testBridgeConfig(), testOperations(mock))
	if err != nil {
		t.Fatal(err)
	}
	mock.fail = "VethDelete " + state.hostVeth
	if err := state.cleanup(); err == nil {
		t.Fatal("cleanup unexpectedly succeeded")
	}
	bridgeDeletes := countPrefix(mock.ops, "BridgeDel ")
	mock.fail = ""
	if err := state.cleanup(); err != nil {
		t.Fatal(err)
	}
	if countPrefix(mock.ops, "BridgeDel ") != bridgeDeletes {
		t.Fatalf("bridge was deleted again: %v", mock.ops)
	}
	if state.ownedVeth || state.ownedBridge {
		t.Fatal("cleanup retained ownership after successful retry")
	}
}

func TestBridgeCleanupAcceptsKernelRemovedVethAndIsIdempotent(t *testing.T) {
	mock := &mockNetlinkOps{}
	state, err := setupParentBridgeWithOps(testBridgeConfig(), testOperations(mock))
	if err != nil {
		t.Fatal(err)
	}
	mock.removeVethPair(state.hostVeth)
	if err := state.cleanup(); err != nil {
		t.Fatalf("cleanup after child namespace teardown = %v", err)
	}
	if state.ownedVeth || state.ownedBridge || len(mock.links) != 0 {
		t.Fatalf("cleanup retained resources: veth=%v bridge=%v links=%v", state.ownedVeth, state.ownedBridge, mock.links)
	}
	operations := len(mock.ops)
	if err := state.cleanup(); err != nil {
		t.Fatalf("second cleanup = %v", err)
	}
	if len(mock.ops) != operations {
		t.Fatalf("second cleanup performed operations: %v", mock.ops[operations:])
	}
}

func TestBridgeCleanupAcceptsExternallyRemovedBridge(t *testing.T) {
	mock := &mockNetlinkOps{}
	state, err := setupParentBridgeWithOps(testBridgeConfig(), testOperations(mock))
	if err != nil {
		t.Fatal(err)
	}
	mock.removeLink(state.bridge)
	if err := state.cleanup(); err != nil {
		t.Fatalf("cleanup after bridge removal = %v", err)
	}
	if state.ownedVeth || state.ownedBridge {
		t.Fatalf("cleanup retained ownership: veth=%v bridge=%v", state.ownedVeth, state.ownedBridge)
	}
}

func TestBridgeCleanupRetainsLinkOwnershipAfterDeleteFailure(t *testing.T) {
	mock := &mockNetlinkOps{}
	state, err := setupParentBridgeWithOps(testBridgeConfig(), testOperations(mock))
	if err != nil {
		t.Fatal(err)
	}
	mock.fail = "VethDelete " + state.hostVeth
	if err := state.cleanup(); err == nil {
		t.Fatal("cleanup unexpectedly succeeded")
	}
	if !state.ownedVeth || state.ownedBridge {
		t.Fatalf("ownership after genuine veth failure: veth=%v bridge=%v", state.ownedVeth, state.ownedBridge)
	}
}

func TestBridgeCleanupAcceptsFailedDeleteAfterLinkDisappears(t *testing.T) {
	mock := &mockNetlinkOps{}
	state, err := setupParentBridgeWithOps(testBridgeConfig(), testOperations(mock))
	if err != nil {
		t.Fatal(err)
	}
	mock.fail = "VethDelete " + state.hostVeth
	mock.removeOnFailure = map[string]bool{state.hostVeth: true}
	if err := state.cleanup(); err != nil {
		t.Fatalf("cleanup after confirmed veth disappearance = %v", err)
	}
	if state.ownedVeth || state.ownedBridge {
		t.Fatalf("cleanup retained ownership: veth=%v bridge=%v", state.ownedVeth, state.ownedBridge)
	}
}

func TestBridgeCleanupRetainsOwnershipWhenLinkInspectionFails(t *testing.T) {
	mock := &mockNetlinkOps{}
	state, err := setupParentBridgeWithOps(testBridgeConfig(), testOperations(mock))
	if err != nil {
		t.Fatal(err)
	}
	mock.fail = "VethDelete " + state.hostVeth
	mock.inspectErr = errors.New("link inspection failed")
	err = state.cleanup()
	if err == nil || !strings.Contains(err.Error(), "simulated failure") || !strings.Contains(err.Error(), "link inspection failed") {
		t.Fatalf("cleanup error = %v, want deletion and inspection errors", err)
	}
	if !state.ownedVeth {
		t.Fatal("cleanup cleared ownership after failed inspection")
	}
}

func containsOperation(ops []string, want string) bool {
	for _, op := range ops {
		if op == want {
			return true
		}
	}
	return false
}

func containsOperationPrefix(ops []string, prefix string) bool {
	for _, op := range ops {
		if strings.HasPrefix(op, prefix) {
			return true
		}
	}
	return false
}

func operationIndex(ops []string, want string) int {
	for index, op := range ops {
		if op == want {
			return index
		}
	}
	return -1
}

func countPrefix(ops []string, prefix string) int {
	count := 0
	for _, op := range ops {
		if strings.HasPrefix(op, prefix) {
			count++
		}
	}
	return count
}

var _ netlinkOps = (*mockNetlinkOps)(nil)
var _ firewallOps = (*mockFirewallOps)(nil)
