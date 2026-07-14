//go:build linux

package network

import (
	"errors"
	"net"
	"testing"
)

type mockNetlinkOps struct {
	ops []string
}

func (m *mockNetlinkOps) BridgeAdd(name string) error {
	m.ops = append(m.ops, "BridgeAdd "+name)
	return nil
}

func (m *mockNetlinkOps) BridgeDel(name string) error {
	m.ops = append(m.ops, "BridgeDel "+name)
	return nil
}

func (m *mockNetlinkOps) VethCreate(name, peer string) error {
	m.ops = append(m.ops, "VethCreate "+name+" "+peer)
	return nil
}

func (m *mockNetlinkOps) VethDelete(name string) error {
	m.ops = append(m.ops, "VethDelete "+name)
	return nil
}

func (m *mockNetlinkOps) LinkSetMaster(link, master string) error {
	m.ops = append(m.ops, "LinkSetMaster "+link+" "+master)
	return nil
}

func (m *mockNetlinkOps) LinkSetNoMaster(link string) error {
	m.ops = append(m.ops, "LinkSetNoMaster "+link)
	return nil
}

func (m *mockNetlinkOps) LinkSetUp(name string) error {
	m.ops = append(m.ops, "LinkSetUp "+name)
	return nil
}

func (m *mockNetlinkOps) LinkSetDown(name string) error {
	m.ops = append(m.ops, "LinkSetDown "+name)
	return nil
}

func (m *mockNetlinkOps) LinkSetMAC(name string, addr net.HardwareAddr) error {
	m.ops = append(m.ops, "LinkSetMAC "+name+" "+addr.String())
	return nil
}

func (m *mockNetlinkOps) LinkSetName(oldName, newName string) error {
	m.ops = append(m.ops, "LinkSetName "+oldName+" "+newName)
	return nil
}

func (m *mockNetlinkOps) AddrAdd(iface, ip string) error {
	m.ops = append(m.ops, "AddrAdd "+iface+" "+ip)
	return nil
}

func (m *mockNetlinkOps) AddrDel(iface, ip string) error {
	m.ops = append(m.ops, "AddrDel "+iface+" "+ip)
	return nil
}

type failingNetlinkOps struct {
	mockNetlinkOps
	failAfter int
}

func (f *failingNetlinkOps) BridgeAdd(name string) error {
	if f.failAfter == 0 {
		return errors.New("simulated failure")
	}
	f.failAfter--
	return f.mockNetlinkOps.BridgeAdd(name)
}

func (f *failingNetlinkOps) VethCreate(name, peer string) error {
	if f.failAfter == 0 {
		return errors.New("simulated failure")
	}
	f.failAfter--
	return f.mockNetlinkOps.VethCreate(name, peer)
}

func (f *failingNetlinkOps) LinkSetMaster(link, master string) error {
	if f.failAfter == 0 {
		return errors.New("simulated failure")
	}
	f.failAfter--
	return f.mockNetlinkOps.LinkSetMaster(link, master)
}

func (f *failingNetlinkOps) AddrAdd(iface, ip string) error {
	if f.failAfter == 0 {
		return errors.New("simulated failure")
	}
	f.failAfter--
	return f.mockNetlinkOps.AddrAdd(iface, ip)
}

func (f *failingNetlinkOps) BridgeDel(name string) error {
	return f.mockNetlinkOps.BridgeDel(name)
}

func (f *failingNetlinkOps) LinkSetNoMaster(link string) error {
	return f.mockNetlinkOps.LinkSetNoMaster(link)
}

func (f *failingNetlinkOps) VethDelete(name string) error {
	return f.mockNetlinkOps.VethDelete(name)
}

func (f *failingNetlinkOps) LinkSetUp(name string) error {
	return f.mockNetlinkOps.LinkSetUp(name)
}

func (f *failingNetlinkOps) LinkSetDown(name string) error {
	return f.mockNetlinkOps.LinkSetDown(name)
}

func (f *failingNetlinkOps) LinkSetMAC(name string, addr net.HardwareAddr) error {
	return f.mockNetlinkOps.LinkSetMAC(name, addr)
}

func (f *failingNetlinkOps) LinkSetName(oldName, newName string) error {
	return f.mockNetlinkOps.LinkSetName(oldName, newName)
}

func (f *failingNetlinkOps) AddrDel(iface, ip string) error {
	return f.mockNetlinkOps.AddrDel(iface, ip)
}

func TestSetupParentBridge_CleanupOnFailure(t *testing.T) {
	cfg := BridgeConfig{
		BridgeName:     "sb0",
		Subnet:         "10.0.100.0/24",
		GatewayIP:      "10.0.100.1",
		ContainerIP:    "10.0.100.2",
		HostVethName:   "veth-host",
		NSVethName:     "veth-ns",
		ContainerIface: "eth0",
	}

	tests := []struct {
		name      string
		failAfter int
		wantErr   bool
		wantOps   []string
	}{
		{
			name:      "fail at veth create cleans bridge",
			failAfter: 1,
			wantErr:   true,
			wantOps:   []string{"BridgeAdd sb0"},
		},
		{
			name:      "fail at link set master cleans veth and bridge",
			failAfter: 2,
			wantErr:   true,
			wantOps:   []string{"BridgeAdd sb0", "VethCreate veth-host veth-ns", "VethDelete veth-host", "BridgeDel sb0"},
		},
		{
			name:      "fail at addr add cleans veth and bridge",
			failAfter: 3,
			wantErr:   true,
			wantOps:   []string{"BridgeAdd sb0", "VethCreate veth-host veth-ns", "LinkSetMaster veth-host sb0", "LinkSetNoMaster veth-host", "VethDelete veth-host", "BridgeDel sb0"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := &failingNetlinkOps{failAfter: tt.failAfter}
			netlinkOps = mock

			state, err := SetupParentBridge(cfg)
			if tt.wantErr && err == nil {
				t.Fatal("SetupParentBridge() expected error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("SetupParentBridge() unexpected error = %v", err)
			}
			if tt.wantErr && state != nil {
				t.Fatal("SetupParentBridge() returned non-nil state on error")
			}

			got := mock.mockNetlinkOps.ops
			if len(got) != len(tt.wantOps) {
				t.Fatalf("ops count = %d, want %d\ngot:  %v\nwant: %v", len(got), len(tt.wantOps), got, tt.wantOps)
			}
			for i := range tt.wantOps {
				if got[i] != tt.wantOps[i] {
					t.Errorf("ops[%d] = %q, want %q", i, got[i], tt.wantOps[i])
				}
			}
		})
	}
}
