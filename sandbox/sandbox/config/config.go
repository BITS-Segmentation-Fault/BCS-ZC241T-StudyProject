package config

import (
	"errors"
	"fmt"
	"strings"

	"sandbox/demo/network"
)

// Define the three-tiered progressive storage allocation parameters.
type StorageConfig struct {
	InitialLimitMB    int    `yaml:"initial_limit_mb"`
	AbsoluteMaximumMB int    `yaml:"absolute_maximum_mb"`
	ExpansionPolicy   string `yaml:"expansion_policy"`
	IncrementStepMB   int    `yaml:"increment_step_mb"`
}

type SeccompAction string

const (
	ActionKill  SeccompAction = "kill"
	ActionTrap  SeccompAction = "trap"
	ActionLog   SeccompAction = "log"
	ActionAllow SeccompAction = "allow"
)

func (a SeccompAction) IsValid() bool {
	switch a {
	case ActionKill, ActionTrap, ActionLog, ActionAllow:
		return true
	default:
		return false
	}
}

// Define a mapping from a host path into the container's view.
type BindMount struct {
	HostPath      string `yaml:"host_path"`
	ContainerPath string `yaml:"container_path"`
	ReadOnly      bool   `yaml:"read_only"`
}

// Representation of the full structural runtime parameters for the sandbox container.
type Config struct {
	BinaryPath           string              `yaml:"binary_path"`
	Args                 []string            `yaml:"args"`
	EnvVars              []string            `yaml:"env_vars"`
	ReadOnlyRoot         bool                `yaml:"read_only_root"`
	SeccompDefaultAction SeccompAction       `yaml:"seccomp_default_action"`
	BlockedSyscalls      []string            `yaml:"blocked_syscalls"`
	DropCapabilities     []string            `yaml:"drop_capabilities"`
	Storage              StorageConfig       `yaml:"storage"`
	CPULimitPercent      int                 `yaml:"cpu_limit_percent"`
	MemoryLimitGB        int                 `yaml:"memory_limit_gb"`
	MaxProcesses         int                 `yaml:"max_processes"`
	NetworkMode          network.NetworkMode `yaml:"network_mode"`
	BridgeConfig         network.BridgeConfig `yaml:"bridge"`
	WorkingDir           string              `yaml:"working_dir"`
	RootFSSource         string              `yaml:"rootfs_source"`
	BindMounts           []BindMount         `yaml:"bind_mounts"`
	DNSServers           []string            `yaml:"dns_servers"`

	Command      []string `yaml:"command"`
	EnvWhitelist []string `yaml:"env_whitelist"`
}

// Provide secure baseline parameters that maximise host protection.
func DefaultConfig() Config {
	return Config{
		BinaryPath:           "",
		Args:                 []string{},
		EnvVars:              []string{"PATH=/bin:/usr/bin", "TERM=xterm"},
		ReadOnlyRoot:         true,
		SeccompDefaultAction: ActionKill,
		BlockedSyscalls:      []string{"mount", "reboot", "ptrace", "swapon", "syslog"},
		DropCapabilities:     []string{"CAP_SYS_ADMIN", "CAP_NET_ADMIN", "CAP_SYS_PTRACE", "CAP_SYS_MODULE", "CAP_SYS_RAWIO", "CAP_SYS_BOOT"},
		Storage: StorageConfig{
			InitialLimitMB:    100,
			AbsoluteMaximumMB: 500,
			ExpansionPolicy:   "none",
			IncrementStepMB:   0,
		},
		CPULimitPercent: 100,
		MemoryLimitGB:   1,
		MaxProcesses:    100,
		NetworkMode:     network.None,
		BridgeConfig:    network.DefaultBridgeConfig(),
		WorkingDir:      "/",
		RootFSSource:    "/var/lib/sandbox/rootfs",
		BindMounts:      []BindMount{},
		DNSServers:      []string{},
		Command:         []string{},
		EnvWhitelist:    []string{},
	}
}

// Review the structural sanity of runtime configurations.
func (c *Config) Validate() error {
	if !c.NetworkMode.IsValid() {
		return fmt.Errorf("value_error: invalid network mode %q", c.NetworkMode)
	}

	if c.NetworkMode == network.Bridge {
		if err := c.BridgeConfig.Validate(); err != nil {
			return fmt.Errorf("value_error: bridge config: %v", err)
		}
	}

	if c.BinaryPath != "" {
		if strings.TrimSpace(c.BinaryPath) == "" {
			return errors.New("value_error: binary_path cannot be only whitespace")
		}
	} else if len(c.Command) == 0 {
		return errors.New("value_error: either binary_path or command must be provided")
	}

	for _, arg := range c.Args {
		if strings.TrimSpace(arg) == "" {
			return errors.New("value_error: args element is empty or only whitespace")
		}
	}

	if len(c.Command) > 0 {
		for _, arg := range c.Command {
			if strings.TrimSpace(arg) == "" {
				return errors.New("value_error: command element is empty or only whitespace")
			}
		}
	}

	if !c.SeccompDefaultAction.IsValid() {
		return fmt.Errorf("value_error: invalid seccomp_default_action %q", c.SeccompDefaultAction)
	}

	for _, sc := range c.BlockedSyscalls {
		if strings.TrimSpace(sc) == "" {
			return errors.New("value_error: blocked_syscalls contains empty entry")
		}
	}

	for _, cap := range c.DropCapabilities {
		if strings.TrimSpace(cap) == "" {
			return errors.New("value_error: drop_capabilities contains empty entry")
		}
	}

	s := c.Storage
	if s.InitialLimitMB <= 0 || s.AbsoluteMaximumMB <= 0 {
		return errors.New("value_error: storage limit values must be positive integers greater than zero")
	}
	if s.InitialLimitMB > s.AbsoluteMaximumMB {
		return errors.New("value_error: initial storage allocation cannot cross absolute maximum boundary")
	}

	policy := strings.ToLower(s.ExpansionPolicy)
	if policy != "none" && policy != "automatic" && policy != "manual" {
		return errors.New("value_error: expansion_policy must be 'none', 'automatic', or 'manual'")
	}

	if (policy == "automatic" || policy == "manual") && s.IncrementStepMB <= 0 {
		return errors.New("value_error: increment_step_mb must be > 0 when expansion is enabled")
	}

	if c.CPULimitPercent < 0 || c.CPULimitPercent > 100 {
		return errors.New("value_error: cpu_limit_percent must be between 0 and 100")
	}

	if c.MemoryLimitGB < 0 {
		return errors.New("value_error: memory_limit_gb cannot be negative")
	}

	if c.MaxProcesses < 0 {
		return errors.New("value_error: max_processes cannot be negative")
	}

	if c.RootFSSource != "" && strings.TrimSpace(c.RootFSSource) == "" {
		return errors.New("value_error: rootfs_source cannot be only whitespace")
	}

	for _, bm := range c.BindMounts {
		if strings.TrimSpace(bm.HostPath) == "" {
			return errors.New("value_error: bind_mount host_path cannot be empty")
		}
		if strings.TrimSpace(bm.ContainerPath) == "" {
			return errors.New("value_error: bind_mount container_path cannot be empty")
		}
	}

	for _, dns := range c.DNSServers {
		if strings.TrimSpace(dns) == "" {
			return errors.New("value_error: dns_servers contains empty entry")
		}
	}

	return nil
}
