package network

import (
	"bytes"
	"net"
	"strings"
	"testing"
)

func TestNetworkMode_ParityAndEdgeCases(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		wantMode    NetworkMode
		wantErr     bool
		errContains string
	}{
		{
			name:     "Valid: host mode matching Python default",
			input:    "host",
			wantMode: Host,
			wantErr:  false,
		},
		{
			name:     "Valid: none mode",
			input:    "none",
			wantMode: None,
			wantErr:  false,
		},
		{
			name:     "Valid: bridge mode",
			input:    "bridge",
			wantMode: Bridge,
			wantErr:  false,
		},
		{
			name:        "Edge Case: Case Sensitivity (Python Enums are strict)",
			input:       "Host",
			wantMode:    "",
			wantErr:     true,
			errContains: "is not a valid NetworkMode",
		},
		{
			name:        "Edge Case: All caps input",
			input:       "HOST",
			wantMode:    "",
			wantErr:     true,
			errContains: "is not a valid NetworkMode",
		},
		{
			name:        "Edge Case: Empty String Input",
			input:       "",
			wantMode:    "",
			wantErr:     true,
			errContains: "is not a valid NetworkMode",
		},
		{
			name:        "Edge Case: Trailing or Leading Whitespace",
			input:       " host ",
			wantMode:    "",
			wantErr:     true,
			errContains: "is not a valid NetworkMode",
		},
		{
			name:        "Edge Case: Malicious/Unexpected Input",
			input:       "../invalid_mode_or_injection",
			wantMode:    "",
			wantErr:     true,
			errContains: "is not a valid NetworkMode",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotMode, err := ParseNetworkMode(tt.input)

			if (err != nil) != tt.wantErr {
				t.Fatalf("ParseNetworkMode() error = %v, wantErr %v", err, tt.wantErr)
			}

			if tt.wantErr {
				if !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("ParseNetworkMode() error = %q, expected to contain %q", err.Error(), tt.errContains)
				}
				return
			}

			if gotMode != tt.wantMode {
				t.Errorf("ParseNetworkMode() gotMode = %q, wantMode %q", gotMode, tt.wantMode)
			}
		})
	}
}

func TestRequiresNetNS(t *testing.T) {
	tests := []struct {
		mode NetworkMode
		want bool
	}{
		{Host, false},
		{None, true},
		{Bridge, true},
	}
	for _, tt := range tests {
		t.Run(string(tt.mode), func(t *testing.T) {
			if got := tt.mode.RequiresNetNS(); got != tt.want {
				t.Errorf("%v.RequiresNetNS() = %v, want %v", tt.mode, got, tt.want)
			}
		})
	}
}

func TestDefaultBridgeConfig_Valid(t *testing.T) {
	cfg := DefaultBridgeConfig()
	if err := cfg.Validate(); err != nil {
		t.Errorf("DefaultBridgeConfig().Validate() error = %v", err)
	}
}

func TestGenerateRandomMAC_Deterministic(t *testing.T) {
	r := strings.NewReader("\x01\x02\x03\x04\x05")
	mac, err := GenerateRandomMAC(r)
	if err != nil {
		t.Fatalf("GenerateRandomMAC() error = %v", err)
	}
	want := net.HardwareAddr{0x02, 0x01, 0x02, 0x03, 0x04, 0x05}
	if !bytes.Equal(mac, want) {
		t.Errorf("GenerateRandomMAC() = %s, want %s", mac, want)
	}
}

func TestGenerateRandomMAC_LocallyAdministered(t *testing.T) {
	mac, err := GenerateRandomMAC(nil)
	if err != nil {
		t.Fatalf("GenerateRandomMAC() error = %v", err)
	}
	if len(mac) != 6 {
		t.Errorf("GenerateRandomMAC() returned %d bytes, want 6", len(mac))
	}
	if mac[0]&0x02 != 0x02 {
		t.Errorf("GenerateRandomMAC() first byte %02x: bit 1 not set (not locally administered)", mac[0])
	}
	if mac[0]&0x01 != 0x00 {
		t.Errorf("GenerateRandomMAC() first byte %02x: bit 0 set (multicast)", mac[0])
	}
}

func TestBridgeConfig_Validate_Valid(t *testing.T) {
	cfg := BridgeConfig{
		BridgeName:     "sb0",
		Subnet:         "10.0.100.0/24",
		GatewayIP:      "10.0.100.1",
		ContainerIP:    "10.0.100.2",
		HostVethName:   "veth-host",
		NSVethName:     "veth-ns",
		ContainerIface: "eth0",
		MTU:            1500,
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("Validate() error = %v", err)
	}
}

func TestBridgeConfig_Validate_Invalid(t *testing.T) {
	tests := []struct {
		name    string
		cfg     BridgeConfig
		errPart string
	}{
		{
			name:    "empty bridge name",
			cfg:     BridgeConfig{Subnet: "10.0.0.0/24", GatewayIP: "10.0.0.1", ContainerIP: "10.0.0.2", HostVethName: "vh", NSVethName: "vc", ContainerIface: "eth0"},
			errPart: "bridge_name",
		},
		{
			name:    "invalid subnet",
			cfg:     BridgeConfig{BridgeName: "sb0", Subnet: "bad-cidr", GatewayIP: "10.0.0.1", ContainerIP: "10.0.0.2", HostVethName: "vh", NSVethName: "vc", ContainerIface: "eth0"},
			errPart: "invalid subnet",
		},
		{
			name:    "invalid gateway IP",
			cfg:     BridgeConfig{BridgeName: "sb0", Subnet: "10.0.0.0/24", GatewayIP: "not-an-ip", ContainerIP: "10.0.0.2", HostVethName: "vh", NSVethName: "vc", ContainerIface: "eth0"},
			errPart: "invalid gateway IP",
		},
		{
			name:    "invalid container IP",
			cfg:     BridgeConfig{BridgeName: "sb0", Subnet: "10.0.0.0/24", GatewayIP: "10.0.0.1", ContainerIP: "", HostVethName: "vh", NSVethName: "vc", ContainerIface: "eth0"},
			errPart: "invalid container IP",
		},
		{
			name:    "empty host veth name",
			cfg:     BridgeConfig{BridgeName: "sb0", Subnet: "10.0.0.0/24", GatewayIP: "10.0.0.1", ContainerIP: "10.0.0.2", HostVethName: "", NSVethName: "vc", ContainerIface: "eth0"},
			errPart: "host_veth_name",
		},
		{
			name:    "empty ns veth name",
			cfg:     BridgeConfig{BridgeName: "sb0", Subnet: "10.0.0.0/24", GatewayIP: "10.0.0.1", ContainerIP: "10.0.0.2", HostVethName: "vh", NSVethName: "", ContainerIface: "eth0"},
			errPart: "ns_veth_name",
		},
		{
			name:    "empty container iface",
			cfg:     BridgeConfig{BridgeName: "sb0", Subnet: "10.0.0.0/24", GatewayIP: "10.0.0.1", ContainerIP: "10.0.0.2", HostVethName: "vh", NSVethName: "vc", ContainerIface: ""},
			errPart: "container_iface",
		},
		{
			name:    "gateway outside subnet",
			cfg:     BridgeConfig{BridgeName: "sb0", Subnet: "10.0.0.0/24", GatewayIP: "10.0.1.1", ContainerIP: "10.0.0.2", HostVethName: "vh", NSVethName: "vc", ContainerIface: "eth0", MTU: 1500},
			errPart: "belong to subnet",
		},
		{
			name:    "interface name too long",
			cfg:     BridgeConfig{BridgeName: "this-name-is-too-long", Subnet: "10.0.0.0/24", GatewayIP: "10.0.0.1", ContainerIP: "10.0.0.2", HostVethName: "vh", NSVethName: "vc", ContainerIface: "eth0", MTU: 1500},
			errPart: "interface-name limit",
		},
		{
			name:    "invalid MTU",
			cfg:     BridgeConfig{BridgeName: "sb0", Subnet: "10.0.0.0/24", GatewayIP: "10.0.0.1", ContainerIP: "10.0.0.2", HostVethName: "vh", NSVethName: "vc", ContainerIface: "eth0", MTU: 1},
			errPart: "mtu",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.Validate()
			if err == nil {
				t.Fatal("Validate() expected error, got nil")
			}
			if !strings.Contains(err.Error(), tt.errPart) {
				t.Errorf("Validate() error = %q, want part %q", err, tt.errPart)
			}
		})
	}
}
