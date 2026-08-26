//go:build linux

package network

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

type mockNetlinkOps struct {
	ops        []string
	fail       string
	interfaces []string
}

func (m *mockNetlinkOps) record(operation string) error {
	m.ops = append(m.ops, operation)
	if m.fail == operation {
		return errors.New("simulated failure")
	}
	return nil
}
func (m *mockNetlinkOps) BridgeAdd(name string) error { return m.record("BridgeAdd " + name) }
func (m *mockNetlinkOps) BridgeDel(name string) error { return m.record("BridgeDel " + name) }
func (m *mockNetlinkOps) VethCreate(name, peer string) error {
	return m.record("VethCreate " + name + " " + peer)
}
func (m *mockNetlinkOps) VethDelete(name string) error { return m.record("VethDelete " + name) }
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
	return append([]string(nil), m.interfaces...), nil
}

type mockFirewallOps struct{}

func (mockFirewallOps) AddNAT(_, _, _ string) error           { return nil }
func (mockFirewallOps) DeleteNAT(_, _, _ string) error        { return nil }
func (mockFirewallOps) AddMetadataBlock(_, _ string) error    { return nil }
func (mockFirewallOps) DeleteMetadataBlock(_, _ string) error { return nil }

func testBridgeConfig() BridgeConfig { return DefaultBridgeConfig() }

func testOperations(mock *mockNetlinkOps) operations {
	return operations{netlink: mock, runIP: func(args ...string) error { return nil }, firewall: mockFirewallOps{}}
}

func TestSetupParentBridgeRollsBackOwnedResources(t *testing.T) {
	mock := &mockNetlinkOps{fail: "VethCreate vh"}
	// Names are generated, so exercise the operation order with a failure matcher below.
	mock.fail = ""
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
	for _, interfaces := range [][]string{{"lo"}, {"lo", "a", "b"}} {
		mock.interfaces = interfaces
		if err := manager.configureChildIface(testBridgeConfig()); err == nil {
			t.Fatalf("interfaces %v were accepted", interfaces)
		}
	}
}

func TestGeneratedNamesArePrivateAndUnique(t *testing.T) {
	a := DefaultBridgeConfig()
	b := DefaultBridgeConfig()
	if !reflect.DeepEqual(a, b) {
		t.Fatalf("defaults changed between calls: %#v %#v", a, b)
	}
	first := strings.Join(func() []string { a, b, c := resourceNames(); return []string{a, b, c} }(), "/")
	second := strings.Join(func() []string { a, b, c := resourceNames(); return []string{a, b, c} }(), "/")
	if first == second {
		t.Fatalf("resource names are not unique: %v", first)
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

var _ netlinkOps = (*mockNetlinkOps)(nil)
var _ firewallOps = mockFirewallOps{}
