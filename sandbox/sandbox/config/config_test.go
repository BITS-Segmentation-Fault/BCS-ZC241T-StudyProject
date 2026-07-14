package config

import (
	"strings"
	"testing"

	"sandbox/demo/network"
)

func TestConfig_ValidationAndParity(t *testing.T) {
	tests := []struct {
		name        string
		inputConfig Config
		wantErr     bool
		errContains string
	}{
		{
			name: "Valid: minimal binary_path",
			inputConfig: Config{
				BinaryPath:          "/bin/echo",
				SeccompDefaultAction: ActionKill,
				Storage: StorageConfig{
					InitialLimitMB:    100,
					AbsoluteMaximumMB: 500,
					ExpansionPolicy:   "none",
					IncrementStepMB:   0,
				},
				NetworkMode: network.Host,
			},
			wantErr: false,
		},
		{
			name: "Valid: command fallback",
			inputConfig: Config{
				Command:             []string{"echo", "hello"},
				SeccompDefaultAction: ActionKill,
				Storage: StorageConfig{
					InitialLimitMB:    100,
					AbsoluteMaximumMB: 500,
					ExpansionPolicy:   "none",
					IncrementStepMB:   0,
				},
				NetworkMode: network.Host,
			},
			wantErr: false,
		},
		{
			name: "Valid: full featured config",
			inputConfig: Config{
				BinaryPath:          "/usr/bin/python",
				Args:                []string{"-m", "http.server"},
				EnvVars:             []string{"PATH=/bin", "TERM=xterm"},
				ReadOnlyRoot:        true,
				SeccompDefaultAction: ActionTrap,
				BlockedSyscalls:     []string{"mount", "reboot"},
				DropCapabilities:    []string{"CAP_SYS_ADMIN", "CAP_NET_ADMIN"},
				Storage: StorageConfig{
					InitialLimitMB:    200,
					AbsoluteMaximumMB: 1000,
					ExpansionPolicy:   "automatic",
					IncrementStepMB:   50,
				},
				CPULimitPercent:  50,
				MemoryLimitGB:    2,
				MaxProcesses:     50,
				NetworkMode:      network.None,
				WorkingDir:       "/app",
				RootFSSource:     "/custom/rootfs",
				BindMounts:       []BindMount{{HostPath: "/data", ContainerPath: "/mnt/data", ReadOnly: true}},
				DNSServers:       []string{"8.8.8.8", "1.1.1.1"},
			},
			wantErr: false,
		},
		{
			name: "Valid: seccomp action allow",
			inputConfig: Config{
				BinaryPath:          "/bin/ls",
				SeccompDefaultAction: ActionAllow,
				Storage: StorageConfig{
					InitialLimitMB:    100,
					AbsoluteMaximumMB: 500,
					ExpansionPolicy:   "none",
					IncrementStepMB:   0,
				},
				NetworkMode: network.None,
			},
			wantErr: false,
		},
		{
			name: "Valid: seccomp action log",
			inputConfig: Config{
				BinaryPath:          "/bin/ls",
				SeccompDefaultAction: ActionLog,
				Storage: StorageConfig{
					InitialLimitMB:    100,
					AbsoluteMaximumMB: 500,
					ExpansionPolicy:   "none",
					IncrementStepMB:   0,
				},
				NetworkMode: network.None,
			},
			wantErr: false,
		},
		{
			name: "Valid: bridge mode with valid config",
			inputConfig: Config{
				BinaryPath:          "/bin/echo",
				SeccompDefaultAction: ActionKill,
				Storage: StorageConfig{
					InitialLimitMB:    100,
					AbsoluteMaximumMB: 500,
					ExpansionPolicy:   "none",
					IncrementStepMB:   0,
				},
				NetworkMode:  network.Bridge,
				BridgeConfig: network.DefaultBridgeConfig(),
			},
			wantErr: false,
		},
		{
			name: "Error: bridge mode with empty bridge name",
			inputConfig: Config{
				BinaryPath:          "/bin/echo",
				SeccompDefaultAction: ActionKill,
				Storage: StorageConfig{
					InitialLimitMB:    100,
					AbsoluteMaximumMB: 500,
					ExpansionPolicy:   "none",
					IncrementStepMB:   0,
				},
				NetworkMode: network.Bridge,
				BridgeConfig: network.BridgeConfig{
					BridgeName: "",
					Subnet:     "10.0.0.0/24", GatewayIP: "10.0.0.1",
					ContainerIP: "10.0.0.2", HostVethName: "vh", NSVethName: "vc", ContainerIface: "eth0",
				},
			},
			wantErr:     true,
			errContains: "bridge config: bridge_name cannot be empty",
		},
		{
			name: "Error: no binary_path and no command",
			inputConfig: Config{
				SeccompDefaultAction: ActionKill,
				Storage: StorageConfig{
					InitialLimitMB:    100,
					AbsoluteMaximumMB: 500,
					ExpansionPolicy:   "none",
					IncrementStepMB:   0,
				},
				NetworkMode: network.Host,
			},
			wantErr:     true,
			errContains: "either binary_path or command must be provided",
		},
		{
			name: "Error: invalid seccomp action",
			inputConfig: Config{
				BinaryPath:          "/bin/ls",
				SeccompDefaultAction: SeccompAction("bogus"),
				Storage: StorageConfig{
					InitialLimitMB:    100,
					AbsoluteMaximumMB: 500,
					ExpansionPolicy:   "none",
					IncrementStepMB:   0,
				},
				NetworkMode: network.Host,
			},
			wantErr:     true,
			errContains: "invalid seccomp_default_action",
		},
		{
			name: "Error: invalid network mode",
			inputConfig: Config{
				BinaryPath:          "/bin/ls",
				SeccompDefaultAction: ActionKill,
				Storage: StorageConfig{
					InitialLimitMB:    100,
					AbsoluteMaximumMB: 500,
					ExpansionPolicy:   "none",
					IncrementStepMB:   0,
				},
				NetworkMode: network.NetworkMode("bad"),
			},
			wantErr:     true,
			errContains: "invalid network mode",
		},
		{
			name: "Error: empty command element",
			inputConfig: Config{
				Command:             []string{"ls", ""},
				SeccompDefaultAction: ActionKill,
				Storage: StorageConfig{
					InitialLimitMB:    100,
					AbsoluteMaximumMB: 500,
					ExpansionPolicy:   "none",
					IncrementStepMB:   0,
				},
				NetworkMode: network.Host,
			},
			wantErr:     true,
			errContains: "is empty or only whitespace",
		},
		{
			name: "Error: blocked_syscalls with empty entry",
			inputConfig: Config{
				BinaryPath:          "/bin/ls",
				SeccompDefaultAction: ActionKill,
				BlockedSyscalls:     []string{"mount", ""},
				Storage: StorageConfig{
					InitialLimitMB:    100,
					AbsoluteMaximumMB: 500,
					ExpansionPolicy:   "none",
					IncrementStepMB:   0,
				},
				NetworkMode: network.Host,
			},
			wantErr:     true,
			errContains: "blocked_syscalls contains empty entry",
		},
		{
			name: "Error: drop_capabilities with empty entry",
			inputConfig: Config{
				BinaryPath:          "/bin/ls",
				SeccompDefaultAction: ActionKill,
				DropCapabilities:    []string{"CAP_SYS_ADMIN", ""},
				Storage: StorageConfig{
					InitialLimitMB:    100,
					AbsoluteMaximumMB: 500,
					ExpansionPolicy:   "none",
					IncrementStepMB:   0,
				},
				NetworkMode: network.Host,
			},
			wantErr:     true,
			errContains: "drop_capabilities contains empty entry",
		},
		{
			name: "Error: cpu_limit_percent out of range (negative)",
			inputConfig: Config{
				BinaryPath:          "/bin/ls",
				SeccompDefaultAction: ActionKill,
				CPULimitPercent:     -1,
				Storage: StorageConfig{
					InitialLimitMB:    100,
					AbsoluteMaximumMB: 500,
					ExpansionPolicy:   "none",
					IncrementStepMB:   0,
				},
				NetworkMode: network.Host,
			},
			wantErr:     true,
			errContains: "cpu_limit_percent must be between 0 and 100",
		},
		{
			name: "Error: cpu_limit_percent out of range (above 100)",
			inputConfig: Config{
				BinaryPath:          "/bin/ls",
				SeccompDefaultAction: ActionKill,
				CPULimitPercent:     101,
				Storage: StorageConfig{
					InitialLimitMB:    100,
					AbsoluteMaximumMB: 500,
					ExpansionPolicy:   "none",
					IncrementStepMB:   0,
				},
				NetworkMode: network.Host,
			},
			wantErr:     true,
			errContains: "cpu_limit_percent must be between 0 and 100",
		},
		{
			name: "Error: memory_limit_gb negative",
			inputConfig: Config{
				BinaryPath:          "/bin/ls",
				SeccompDefaultAction: ActionKill,
				MemoryLimitGB:       -1,
				Storage: StorageConfig{
					InitialLimitMB:    100,
					AbsoluteMaximumMB: 500,
					ExpansionPolicy:   "none",
					IncrementStepMB:   0,
				},
				NetworkMode: network.Host,
			},
			wantErr:     true,
			errContains: "memory_limit_gb cannot be negative",
		},
		{
			name: "Error: max_processes negative",
			inputConfig: Config{
				BinaryPath:          "/bin/ls",
				SeccompDefaultAction: ActionKill,
				MaxProcesses:        -1,
				Storage: StorageConfig{
					InitialLimitMB:    100,
					AbsoluteMaximumMB: 500,
					ExpansionPolicy:   "none",
					IncrementStepMB:   0,
				},
				NetworkMode: network.Host,
			},
			wantErr:     true,
			errContains: "max_processes cannot be negative",
		},
		{
			name: "Error: empty bind_mount host_path",
			inputConfig: Config{
				BinaryPath:          "/bin/ls",
				SeccompDefaultAction: ActionKill,
				BindMounts:          []BindMount{{HostPath: "", ContainerPath: "/mnt"}},
				Storage: StorageConfig{
					InitialLimitMB:    100,
					AbsoluteMaximumMB: 500,
					ExpansionPolicy:   "none",
					IncrementStepMB:   0,
				},
				NetworkMode: network.Host,
			},
			wantErr:     true,
			errContains: "bind_mount host_path cannot be empty",
		},
		{
			name: "Error: empty bind_mount container_path",
			inputConfig: Config{
				BinaryPath:          "/bin/ls",
				SeccompDefaultAction: ActionKill,
				BindMounts:          []BindMount{{HostPath: "/data", ContainerPath: ""}},
				Storage: StorageConfig{
					InitialLimitMB:    100,
					AbsoluteMaximumMB: 500,
					ExpansionPolicy:   "none",
					IncrementStepMB:   0,
				},
				NetworkMode: network.Host,
			},
			wantErr:     true,
			errContains: "bind_mount container_path cannot be empty",
		},
		{
			name: "Error: storage initial > absolute",
			inputConfig: Config{
				BinaryPath:          "/bin/ls",
				SeccompDefaultAction: ActionKill,
				Storage: StorageConfig{
					InitialLimitMB:    500,
					AbsoluteMaximumMB: 100,
					ExpansionPolicy:   "none",
					IncrementStepMB:   0,
				},
				NetworkMode: network.Host,
			},
			wantErr:     true,
			errContains: "cannot cross absolute maximum boundary",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.inputConfig.Validate()

			if (err != nil) != tt.wantErr {
				t.Fatalf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}

			if tt.wantErr && !strings.Contains(err.Error(), tt.errContains) {
				t.Errorf("Validate() error msg = %q, expected to contain %q", err.Error(), tt.errContains)
			}
		})
	}
}

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.ReadOnlyRoot != true {
		t.Errorf("DefaultConfig().ReadOnlyRoot = false, want true")
	}
	if cfg.SeccompDefaultAction != ActionKill {
		t.Errorf("DefaultConfig().SeccompDefaultAction = %q, want %q", cfg.SeccompDefaultAction, ActionKill)
	}
	if cfg.NetworkMode != network.None {
		t.Errorf("DefaultConfig().NetworkMode = %q, want %q", cfg.NetworkMode, network.None)
	}
	if cfg.Storage.ExpansionPolicy != "none" {
		t.Errorf("DefaultConfig().Storage.ExpansionPolicy = %q, want %q", cfg.Storage.ExpansionPolicy, "none")
	}
	if cfg.CPULimitPercent != 100 {
		t.Errorf("DefaultConfig().CPULimitPercent = %d, want 100", cfg.CPULimitPercent)
	}
	if cfg.MemoryLimitGB != 1 {
		t.Errorf("DefaultConfig().MemoryLimitGB = %d, want 1", cfg.MemoryLimitGB)
	}
	if cfg.MaxProcesses != 100 {
		t.Errorf("DefaultConfig().MaxProcesses = %d, want 100", cfg.MaxProcesses)
	}
	if len(cfg.BlockedSyscalls) == 0 {
		t.Errorf("DefaultConfig() should have blocked_syscalls")
	}
	if len(cfg.DropCapabilities) == 0 {
		t.Errorf("DefaultConfig() should have drop_capabilities")
	}
}

func TestSeccompActionIsValid(t *testing.T) {
	if !ActionKill.IsValid() {
		t.Error("ActionKill.IsValid() = false")
	}
	if !ActionTrap.IsValid() {
		t.Error("ActionTrap.IsValid() = false")
	}
	if !ActionLog.IsValid() {
		t.Error("ActionLog.IsValid() = false")
	}
	if !ActionAllow.IsValid() {
		t.Error("ActionAllow.IsValid() = false")
	}
	if SeccompAction("bogus").IsValid() {
		t.Error("SeccompAction('bogus').IsValid() = true")
	}
}
