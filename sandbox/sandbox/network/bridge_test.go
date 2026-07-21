//go:build linux

package network

import (
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
)

type mockNetlinkOps struct {
	mu   sync.Mutex
	ops  []string
	fail string
}

func (m *mockNetlinkOps) record(operation string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
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
func (m *mockNetlinkOps) LinkSetNoMaster(link string) error {
	return m.record("LinkSetNoMaster " + link)
}
func (m *mockNetlinkOps) LinkSetUp(name string) error   { return m.record("LinkSetUp " + name) }
func (m *mockNetlinkOps) LinkSetDown(name string) error { return m.record("LinkSetDown " + name) }
func (m *mockNetlinkOps) LinkSetMTU(name string, mtu int) error {
	return m.record("LinkSetMTU " + name)
}
func (m *mockNetlinkOps) LinkSetMAC(name string, addr net.HardwareAddr) error {
	return m.record("LinkSetMAC " + name)
}
func (m *mockNetlinkOps) LinkSetName(oldName, newName string) error {
	return m.record("LinkSetName " + oldName + " " + newName)
}
func (m *mockNetlinkOps) AddrAdd(iface, ip string) error {
	return m.record("AddrAdd " + iface + " " + ip)
}
func (m *mockNetlinkOps) AddrDel(iface, ip string) error {
	return m.record("AddrDel " + iface + " " + ip)
}

type mockFirewallOps struct {
	mu    sync.Mutex
	added []string
	fail  bool
}

func (m *mockFirewallOps) AddNAT(_, _, label string) error {
	if m.fail {
		return errors.New("simulated firewall failure")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.added = append(m.added, label)
	return nil
}
func (m *mockFirewallOps) DeleteNAT(_, _, label string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.added = removeString(m.added, label)
	return nil
}
func (m *mockFirewallOps) AddMetadataBlock(_, _ string) error    { return nil }
func (m *mockFirewallOps) DeleteMetadataBlock(_, _ string) error { return nil }

func testBridgeConfig() BridgeConfig {
	return BridgeConfig{BridgeName: "sb-test", Subnet: "10.0.100.0/24", GatewayIP: "10.0.100.1", ContainerIP: "10.0.100.2", HostVethName: "vh-test", NSVethName: "vc-test", ContainerIface: "eth0", MTU: 1500}
}

func testOperations(mock *mockNetlinkOps, firewall *mockFirewallOps) Operations {
	return Operations{Netlink: mock, RunIP: func(args ...string) error { return nil }, Firewall: firewall}
}

func TestSetupParentBridgeRollsBackOnlyOwnedResources(t *testing.T) {
	for _, test := range []struct {
		name string
		fail string
		want []string
	}{
		{name: "veth", fail: "VethCreate vh-test vc-test", want: []string{"BridgeAdd sb-test", "VethCreate vh-test vc-test", "BridgeDel sb-test"}},
		{name: "address", fail: "AddrAdd sb-test 10.0.100.1/24", want: []string{"BridgeAdd sb-test", "VethCreate vh-test vc-test", "LinkSetMaster vh-test sb-test", "AddrAdd sb-test 10.0.100.1/24", "LinkSetNoMaster vh-test", "VethDelete vh-test", "BridgeDel sb-test"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			mock := &mockNetlinkOps{fail: test.fail}
			state, err := SetupParentBridgeWithOps(testBridgeConfig(), testOperations(mock, &mockFirewallOps{}))
			if err == nil || state != nil {
				t.Fatalf("SetupParentBridgeWithOps() state=%v err=%v", state, err)
			}
			if got := mock.ops; strings.Join(got, "\x00") != strings.Join(test.want, "\x00") {
				t.Fatalf("operations = %v, want %v", got, test.want)
			}
		})
	}
}

func TestBridgeTeardownIsIdempotent(t *testing.T) {
	mock := &mockNetlinkOps{}
	state, err := SetupParentBridgeWithOps(testBridgeConfig(), testOperations(mock, &mockFirewallOps{}))
	if err != nil {
		t.Fatal(err)
	}
	if err := TeardownParentBridge(state); err != nil {
		t.Fatal(err)
	}
	firstCount := len(mock.ops)
	if err := TeardownParentBridge(state); err != nil {
		t.Fatal(err)
	}
	if len(mock.ops) != firstCount {
		t.Fatalf("second teardown changed operation list: %v", mock.ops)
	}
}

func TestNATRollbackUsesRunOwnedRule(t *testing.T) {
	mock := &mockNetlinkOps{}
	firewall := &mockFirewallOps{fail: true}
	state, err := SetupParentBridgeWithOps(testBridgeConfig(), testOperations(mock, firewall))
	if err != nil {
		t.Fatal(err)
	}
	if err := SetupNATForBridge(state, testBridgeConfig()); err == nil {
		t.Fatal("SetupNATForBridge() accepted an injected firewall failure")
	}
	if state.NAT != nil {
		t.Fatal("failed NAT setup left an owned state")
	}

	firewall.fail = false
	if err := SetupNATForBridge(state, testBridgeConfig()); err != nil {
		t.Fatal(err)
	}
	if err := TeardownParentBridge(state); err != nil {
		t.Fatal(err)
	}
	if len(firewall.added) != 0 {
		t.Fatalf("owned firewall rules remain: %v", firewall.added)
	}
}

func TestBridgeManagersDoNotShareMutableState(t *testing.T) {
	first, second := DefaultBridgeConfig(), DefaultBridgeConfig()
	if first.BridgeName == second.BridgeName || first.HostVethName == second.HostVethName || first.NSVethName == second.NSVethName {
		t.Fatalf("default bridge names are not unique: %#v %#v", first, second)
	}
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			mock := &mockNetlinkOps{}
			state, err := SetupParentBridgeWithOps(testBridgeConfig(), testOperations(mock, &mockFirewallOps{}))
			if err == nil {
				_ = TeardownParentBridge(state)
			}
		}()
	}
	wg.Wait()
}

func removeString(values []string, want string) []string {
	result := values[:0]
	for _, value := range values {
		if value != want {
			result = append(result, value)
		}
	}
	return result
}
