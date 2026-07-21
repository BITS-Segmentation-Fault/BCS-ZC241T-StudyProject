package main

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"sandbox/sandbox/config"
	"sandbox/sandbox/network"
)

func TestMain_CLIParityMatrix(t *testing.T) {
	baseDefaults := config.DefaultConfig()

	tests := []struct {
		name        string
		argv        []string
		want        Args
		wantErr     bool
		errContains string
	}{
		{
			name: "Valid: Simplest baseline command execution",
			argv: []string{"ls"},
			want: Args{
				Config: func() config.Config {
					c := baseDefaults
					c.Command = []string{"ls"}
					c.BinaryPath = ""
					return c
				}(),
				Verbose: false,
			},
			wantErr: false,
		},
		{
			name: "Valid: Full configuration parameters with complex command",
			argv: []string{"--network-mode", "none", "--verbose", "python", "-m", "venv"},
			want: Args{
				Config: func() config.Config {
					c := baseDefaults
					c.NetworkMode = network.None
					c.Command = []string{"python", "-m", "venv"}
					c.BinaryPath = ""
					return c
				}(),
				Verbose: true,
			},
			wantErr: false,
		},
		{
			name: "Valid: network host with verbose",
			argv: []string{"--network-mode", "host", "--verbose", "/bin/sh"},
			want: Args{
				Config: func() config.Config {
					c := baseDefaults
					c.NetworkMode = network.Host
					c.Command = []string{"/bin/sh"}
					c.BinaryPath = ""
					return c
				}(),
				Verbose: true,
			},
			wantErr: false,
		},
		{
			name:        "Error: Missing command positional arguments (Empty input)",
			argv:        []string{},
			want:        Args{},
			wantErr:     true,
			errContains: "either binary_path or command must be provided",
		},
		{
			name:        "Error: Missing command positional arguments (Only flags present)",
			argv:        []string{"--verbose"},
			want:        Args{},
			wantErr:     true,
			errContains: "either binary_path or command must be provided",
		},
		{
			name:        "Error: Unrecognized command-line flag syntax",
			argv:        []string{"--bad-flag", "value", "ls"},
			want:        Args{},
			wantErr:     true,
			errContains: "flag provided but not defined",
		},
		{
			name: "Valid: bridge mode with defaults",
			argv: []string{"--network-mode", "bridge", "curl", "example.com"},
			want: Args{
				Config: func() config.Config {
					c := baseDefaults
					c.NetworkMode = network.Bridge
					c.Command = []string{"curl", "example.com"}
					c.BinaryPath = ""
					return c
				}(),
				Verbose: false,
			},
			wantErr: false,
		},
		{
			name: "Valid: bridge mode with custom subnet",
			argv: []string{"--network-mode", "bridge", "--bridge-subnet", "172.20.0.0/24", "--bridge-gateway", "172.20.0.1", "--bridge-container-ip", "172.20.0.5", "curl", "example.com"},
			want: Args{
				Config: func() config.Config {
					c := baseDefaults
					c.NetworkMode = network.Bridge
					c.BridgeConfig.Subnet = "172.20.0.0/24"
					c.BridgeConfig.GatewayIP = "172.20.0.1"
					c.BridgeConfig.ContainerIP = "172.20.0.5"
					c.Command = []string{"curl", "example.com"}
					c.BinaryPath = ""
					return c
				}(),
				Verbose: false,
			},
			wantErr: false,
		},
		{
			name:        "Error: Invalid network mode variant parsed",
			argv:        []string{"--network-mode", "bad-enum-value", "ls"},
			want:        Args{},
			wantErr:     true,
			errContains: "not a valid NetworkMode",
		},
		{
			name:        "Error: Empty string passed inside the command array",
			argv:        []string{"ls", ""},
			want:        Args{},
			wantErr:     true,
			errContains: "is empty or only whitespace",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseArgs(tt.argv)

			if (err != nil) != tt.wantErr {
				t.Fatalf("ParseArgs() error = %v, wantErr %v", err, tt.wantErr)
			}

			if tt.wantErr {
				if !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("ParseArgs() error string = %q, expected keyword %q", err.Error(), tt.errContains)
				}
				return
			}

			if !equalArgsIgnoringGeneratedBridgeNames(got, tt.want) {
				t.Errorf("ParseArgs() output discrepancy:\ngot  = %+v\nwant = %+v", got, tt.want)
			}
		})
	}
}

func equalArgsIgnoringGeneratedBridgeNames(got, want Args) bool {
	got.Config.BridgeConfig.BridgeName = ""
	got.Config.BridgeConfig.HostVethName = ""
	got.Config.BridgeConfig.NSVethName = ""
	want.Config.BridgeConfig.BridgeName = ""
	want.Config.BridgeConfig.HostVethName = ""
	want.Config.BridgeConfig.NSVethName = ""
	return reflect.DeepEqual(got, want)
}

func TestParseArgs_PreservesConfigValuesWithoutCLIOverrides(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "sandbox.yaml")
	contents := []byte(`
binary_path: /bin/echo
args: [from-config]
network_mode: host
bridge:
  bridge_name: cfg0
  subnet: 172.20.0.0/24
  gateway_ip: 172.20.0.1
  container_ip: 172.20.0.2
  host_veth_name: cfg-veth-h
  ns_veth_name: cfg-veth-c
  container_iface: eth0
storage:
  initial_limit_mb: 20
  absolute_maximum_mb: 40
  expansion_policy: none
  increment_step_mb: 0
`)
	if err := os.WriteFile(configPath, contents, 0600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	got, err := ParseArgs([]string{"--config", configPath})
	if err != nil {
		t.Fatalf("ParseArgs() error = %v", err)
	}

	if got.Config.BinaryPath != "/bin/echo" || !reflect.DeepEqual(got.Config.Args, []string{"from-config"}) {
		t.Fatalf("config command was overwritten: %+v", got.Config)
	}
	if got.Config.NetworkMode != network.Host {
		t.Fatalf("NetworkMode = %q, want %q", got.Config.NetworkMode, network.Host)
	}
	if got.Config.BridgeConfig.BridgeName != "cfg0" {
		t.Fatalf("BridgeName = %q, want cfg0", got.Config.BridgeConfig.BridgeName)
	}
	if got.Config.Storage.InitialLimitMB != 20 || got.Config.Storage.AbsoluteMaximumMB != 40 {
		t.Fatalf("Storage = %+v, want config values", got.Config.Storage)
	}
}

func TestParseArgs_RejectsConflictingCommandForms(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "sandbox.yaml")
	if err := os.WriteFile(configPath, []byte("binary_path: /bin/echo\nargs: [from-config]\n"), 0600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	if _, err := ParseArgs([]string{"--config", configPath, "printf", "hello"}); err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("ParseArgs() error = %v, want conflicting command forms", err)
	}
}

func TestParseArgs_DiscoversConfigAfterOtherFlags(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "sandbox.yaml")
	if err := os.WriteFile(configPath, []byte("binary_path: /bin/echo\nargs: [from-config]\nnetwork_mode: host\n"), 0600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	got, err := ParseArgs([]string{"--verbose", "--config", configPath})
	if err != nil {
		t.Fatalf("ParseArgs() error = %v", err)
	}
	if !got.Verbose || got.Config.NetworkMode != network.Host || got.Config.Args[0] != "from-config" {
		t.Fatalf("config or explicit flag was lost: %+v", got)
	}
}

func TestParseArgs_RejectsDuplicateOptions(t *testing.T) {
	if _, err := ParseArgs([]string{"--verbose", "--verbose", "true"}); err == nil || !strings.Contains(err.Error(), "more than once") {
		t.Fatalf("ParseArgs() error = %v, want duplicate-option error", err)
	}
}

func TestSplitInternalInvocationRequiresLeadingMarker(t *testing.T) {
	if internal, _, err := splitInternalInvocation([]string{"echo", "--internal-child"}); err == nil || internal {
		t.Fatalf("splitInternalInvocation() = internal=%v, err=%v", internal, err)
	}
	if internal, args, err := splitInternalInvocation([]string{"--internal-child", "echo"}); err != nil || !internal || !reflect.DeepEqual(args, []string{"echo"}) {
		t.Fatalf("splitInternalInvocation() = %v, %v, %v", internal, args, err)
	}
}

func TestWithEnvironment_ReplacesExistingValue(t *testing.T) {
	environment := withEnvironment([]string{"PATH=/bin", "GODEBUG=other", "GODEBUG=duplicate"}, "GODEBUG", "pidfd=0")

	var matches []string
	for _, entry := range environment {
		if strings.HasPrefix(entry, "GODEBUG=") {
			matches = append(matches, entry)
		}
	}
	if !reflect.DeepEqual(matches, []string{"GODEBUG=pidfd=0"}) {
		t.Fatalf("GODEBUG entries = %v, want one replacement", matches)
	}
}
