package main

import (
	"reflect"
	"strings"
	"testing"

	"sandbox/demo/config"
	"sandbox/demo/network"
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

			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParseArgs() output discrepancy:\ngot  = %+v\nwant = %+v", got, tt.want)
			}
		})
	}
}
