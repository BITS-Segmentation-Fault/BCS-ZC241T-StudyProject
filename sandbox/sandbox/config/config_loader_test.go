package config

import (
	"strings"
	"testing"

	"sandbox/sandbox/network"
)

func TestLoadConfigFromReader(t *testing.T) {
	tests := []struct {
		name        string
		yamlInput   string
		wantErr     bool
		errContains string
	}{
		{
			name: "Valid: minimal config with binary_path",
			yamlInput: `
binary_path: /bin/echo
network_mode: host
storage:
  initial_limit_mb: 100
  absolute_maximum_mb: 500
  expansion_policy: none
  increment_step_mb: 0
`,
			wantErr: false,
		},
		{
			name: "Valid: full config",
			yamlInput: `
binary_path: /usr/bin/python
args:
  - -m
  - http.server
env_vars:
  - PATH=/bin
  - TERM=xterm
read_only_root: true
seccomp_default_action: trap
blocked_syscalls:
  - mount
  - reboot
  - ptrace
drop_capabilities:
  - CAP_SYS_ADMIN
  - CAP_NET_ADMIN
storage:
  initial_limit_mb: 200
  absolute_maximum_mb: 1000
  expansion_policy: none
  increment_step_mb: 0
cpu_limit_percent: 50
memory_limit_gb: 2
max_processes: 50
network_mode: none
working_dir: /app
rootfs_source: /custom/rootfs
bind_mounts:
  - host_path: /data
    container_path: /mnt/data
    read_only: true
dns_servers:
  - 8.8.8.8
  - 1.1.1.1
`,
			wantErr: false,
		},
		{
			name: "Valid: uses defaults for omitted fields",
			yamlInput: `
binary_path: /bin/echo
`,
			wantErr: false,
		},
		{
			name: "Valid: command fallback",
			yamlInput: `
command:
  - echo
  - hello-world
network_mode: host
`,
			wantErr: false,
		},
		{
			name: "Error: unknown field",
			yamlInput: `
binary_path: /bin/echo
unknown_field: value
`,
			wantErr:     true,
			errContains: "not found in type",
		},
		{
			name: "Error: no binary_path and no command",
			yamlInput: `
network_mode: host
`,
			wantErr:     true,
			errContains: "either binary_path or command must be provided",
		},
		{
			name: "Error: invalid seccomp action",
			yamlInput: `
binary_path: /bin/echo
seccomp_default_action: bogus
`,
			wantErr:     true,
			errContains: "invalid seccomp_default_action",
		},
		{
			name: "Error: invalid network mode",
			yamlInput: `
binary_path: /bin/echo
network_mode: invalid_mode
`,
			wantErr:     true,
			errContains: "invalid network mode",
		},
		{
			name: "Error: cpu percent out of range",
			yamlInput: `
binary_path: /bin/echo
cpu_limit_percent: 150
`,
			wantErr:     true,
			errContains: "cpu_limit_percent must be between 0 and 100",
		},
		{
			name: "Error: bind mount missing host_path",
			yamlInput: `
binary_path: /bin/echo
bind_mounts:
  - container_path: /mnt
`,
			wantErr:     true,
			errContains: "bind_mount host_path cannot be empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := strings.NewReader(tt.yamlInput)
			_, err := LoadConfigFromReader(r)

			if (err != nil) != tt.wantErr {
				t.Fatalf("LoadConfigFromReader() error = %v, wantErr %v", err, tt.wantErr)
			}

			if tt.wantErr && !strings.Contains(err.Error(), tt.errContains) {
				t.Errorf("LoadConfigFromReader() error msg = %q, expected to contain %q", err.Error(), tt.errContains)
			}
		})
	}
}

func TestLoadConfigFromReader_DefaultsPreserved(t *testing.T) {
	input := `
binary_path: /bin/echo
`
	r := strings.NewReader(input)
	cfg, err := LoadConfigFromReader(r)
	if err != nil {
		t.Fatalf("LoadConfigFromReader() failed: %v", err)
	}

	if cfg.ReadOnlyRoot != true {
		t.Errorf("default ReadOnlyRoot = false, want true")
	}
	if cfg.SeccompDefaultAction != ActionKill {
		t.Errorf("default SeccompDefaultAction = %q, want %q", cfg.SeccompDefaultAction, ActionKill)
	}
	if cfg.NetworkMode != network.None {
		t.Errorf("default NetworkMode = %q, want %q", cfg.NetworkMode, network.None)
	}
	if cfg.Storage.ExpansionPolicy != "none" {
		t.Errorf("default ExpansionPolicy = %q, want %q", cfg.Storage.ExpansionPolicy, "none")
	}
	if cfg.CPULimitPercent != 100 {
		t.Errorf("default CPULimitPercent = %d, want 100", cfg.CPULimitPercent)
	}
	if cfg.MemoryLimitGB != 1 {
		t.Errorf("default MemoryLimitGB = %d, want 1", cfg.MemoryLimitGB)
	}
	if cfg.MaxProcesses != 100 {
		t.Errorf("default MaxProcesses = %d, want 100", cfg.MaxProcesses)
	}
	if len(cfg.BlockedSyscalls) == 0 {
		t.Errorf("default BlockedSyscalls is empty")
	}
	if len(cfg.DropCapabilities) == 0 {
		t.Errorf("default DropCapabilities is empty")
	}
	if len(cfg.EnvVars) == 0 {
		t.Errorf("default EnvVars is empty")
	}
	if !strings.Contains(cfg.EnvVars[0], "PATH") {
		t.Errorf("default EnvVars missing PATH")
	}
}

func TestLoadConfigFromReader_OverrideDefaults(t *testing.T) {
	input := `
binary_path: /bin/echo
read_only_root: false
seccomp_default_action: allow
network_mode: host
storage:
  expansion_policy: none
  increment_step_mb: 0
cpu_limit_percent: 75
memory_limit_gb: 4
max_processes: 200
`
	r := strings.NewReader(input)
	cfg, err := LoadConfigFromReader(r)
	if err != nil {
		t.Fatalf("LoadConfigFromReader() failed: %v", err)
	}

	if cfg.ReadOnlyRoot != false {
		t.Errorf("ReadOnlyRoot = true, want false")
	}
	if cfg.SeccompDefaultAction != ActionAllow {
		t.Errorf("SeccompDefaultAction = %q, want %q", cfg.SeccompDefaultAction, ActionAllow)
	}
	if cfg.NetworkMode != network.Host {
		t.Errorf("NetworkMode = %q, want %q", cfg.NetworkMode, network.Host)
	}
	if cfg.Storage.ExpansionPolicy != "none" {
		t.Errorf("ExpansionPolicy = %q, want %q", cfg.Storage.ExpansionPolicy, "none")
	}
	if cfg.Storage.IncrementStepMB != 0 {
		t.Errorf("IncrementStepMB = %d, want 0", cfg.Storage.IncrementStepMB)
	}
	if cfg.CPULimitPercent != 75 {
		t.Errorf("CPULimitPercent = %d, want 75", cfg.CPULimitPercent)
	}
	if cfg.MemoryLimitGB != 4 {
		t.Errorf("MemoryLimitGB = %d, want 4", cfg.MemoryLimitGB)
	}
	if cfg.MaxProcesses != 200 {
		t.Errorf("MaxProcesses = %d, want 200", cfg.MaxProcesses)
	}
}
