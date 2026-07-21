package config

import (
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"strings"

	"sandbox/sandbox/network"
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
	BinaryPath           string               `yaml:"binary_path"`
	Args                 []string             `yaml:"args"`
	EnvVars              []string             `yaml:"env_vars"`
	ReadOnlyRoot         bool                 `yaml:"read_only_root"`
	SeccompDefaultAction SeccompAction        `yaml:"seccomp_default_action"`
	BlockedSyscalls      []string             `yaml:"blocked_syscalls"`
	DropCapabilities     []string             `yaml:"drop_capabilities"`
	Storage              StorageConfig        `yaml:"storage"`
	CPULimitPercent      int                  `yaml:"cpu_limit_percent"`
	MemoryLimitGB        int                  `yaml:"memory_limit_gb"`
	MaxProcesses         int                  `yaml:"max_processes"`
	NetworkMode          network.NetworkMode  `yaml:"network_mode"`
	BridgeConfig         network.BridgeConfig `yaml:"bridge"`
	WorkingDir           string               `yaml:"working_dir"`
	RootFSSource         string               `yaml:"rootfs_source"`
	BindMounts           []BindMount          `yaml:"bind_mounts"`
	DNSServers           []string             `yaml:"dns_servers"`

	Command      []string `yaml:"command"`
	EnvWhitelist []string `yaml:"env_whitelist"`
}

// CommandLine returns the single configured executable form used by the child.
func (c Config) CommandLine() []string {
	if c.BinaryPath != "" {
		command := make([]string, 0, len(c.Args)+1)
		command = append(command, c.BinaryPath)
		command = append(command, c.Args...)
		return command
	}
	return append([]string(nil), c.Command...)
}

// Environment combines explicit values with only the allowlisted host values.
func (c Config) Environment(hostEnvironment []string) []string {
	result := make([]string, 0, len(c.EnvVars)+len(c.EnvWhitelist))
	seen := make(map[string]struct{}, len(c.EnvVars)+len(c.EnvWhitelist))
	for _, entry := range c.EnvVars {
		key, _, _ := strings.Cut(entry, "=")
		if _, exists := seen[key]; exists {
			for i, previous := range result {
				if previousKey, _, _ := strings.Cut(previous, "="); previousKey == key {
					result[i] = entry
					break
				}
			}
			continue
		}
		seen[key] = struct{}{}
		result = append(result, entry)
	}
	allowed := make(map[string]struct{}, len(c.EnvWhitelist))
	for _, key := range c.EnvWhitelist {
		allowed[key] = struct{}{}
	}
	for _, entry := range hostEnvironment {
		key, _, ok := strings.Cut(entry, "=")
		if !ok {
			continue
		}
		if _, ok := allowed[key]; !ok {
			continue
		}
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, entry)
	}
	return result
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
		DropCapabilities:     []string{"ALL"},
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

	if c.BinaryPath != "" && len(c.Command) > 0 {
		return errors.New("value_error: binary_path/args and command are mutually exclusive")
	}
	if len(c.Args) > 0 && c.BinaryPath == "" {
		return errors.New("value_error: args requires binary_path")
	}
	if c.BinaryPath != "" {
		if strings.TrimSpace(c.BinaryPath) == "" {
			return errors.New("value_error: binary_path cannot be only whitespace")
		}
	} else if len(c.Command) == 0 {
		return errors.New("value_error: either binary_path or command must be provided")
	}

	for _, arg := range c.Args {
		if strings.TrimSpace(arg) == "" || strings.IndexByte(arg, 0) >= 0 {
			return errors.New("value_error: args element is empty or only whitespace")
		}
	}

	if len(c.Command) > 0 {
		for _, arg := range c.Command {
			if strings.TrimSpace(arg) == "" || strings.IndexByte(arg, 0) >= 0 {
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
		if !IsKnownCapability(cap) {
			return fmt.Errorf("value_error: unknown capability %q", cap)
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
	if policy != "none" {
		return errors.New("value_error: storage expansion policies are not supported; expansion_policy must be 'none'")
	}
	if s.IncrementStepMB < 0 {
		return errors.New("value_error: increment_step_mb cannot be negative")
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
	if c.RootFSSource != "" && (!filepath.IsAbs(c.RootFSSource) || pathHasParentEscape(c.RootFSSource)) {
		return errors.New("value_error: rootfs_source must be absolute and cannot contain ..")
	}
	if c.WorkingDir != "" && (!filepath.IsAbs(c.WorkingDir) || pathHasParentEscape(c.WorkingDir)) {
		return errors.New("value_error: working_dir must be absolute and cannot contain ..")
	}

	for _, bm := range c.BindMounts {
		if strings.TrimSpace(bm.HostPath) == "" {
			return errors.New("value_error: bind_mount host_path cannot be empty")
		}
		if strings.TrimSpace(bm.ContainerPath) == "" {
			return errors.New("value_error: bind_mount container_path cannot be empty")
		}
		if !filepath.IsAbs(bm.HostPath) || !filepath.IsAbs(bm.ContainerPath) {
			return errors.New("value_error: bind_mount paths must be absolute")
		}
		if pathHasParentEscape(bm.ContainerPath) {
			return fmt.Errorf("value_error: bind_mount container_path %q escapes rootfs", bm.ContainerPath)
		}
	}

	for _, dns := range c.DNSServers {
		if strings.TrimSpace(dns) == "" || net.ParseIP(dns) == nil {
			return fmt.Errorf("value_error: dns_servers contains invalid address %q", dns)
		}
	}
	for _, entry := range c.EnvVars {
		key, _, ok := strings.Cut(entry, "=")
		if !ok || key == "" || strings.IndexByte(entry, 0) >= 0 {
			return fmt.Errorf("value_error: env_vars entry %q must be KEY=VALUE without NUL", entry)
		}
	}
	for _, key := range c.EnvWhitelist {
		if key == "" || strings.ContainsAny(key, "=\x00") {
			return fmt.Errorf("value_error: env_whitelist key %q is invalid", key)
		}
	}

	return nil
}

var knownCapabilities = map[string]struct{}{
	"CAP_CHOWN": {}, "CAP_DAC_OVERRIDE": {}, "CAP_DAC_READ_SEARCH": {}, "CAP_FOWNER": {},
	"CAP_FSETID": {}, "CAP_KILL": {}, "CAP_SETGID": {}, "CAP_SETUID": {}, "CAP_SETPCAP": {},
	"CAP_LINUX_IMMUTABLE": {}, "CAP_NET_BIND_SERVICE": {}, "CAP_NET_BROADCAST": {}, "CAP_NET_ADMIN": {},
	"CAP_NET_RAW": {}, "CAP_IPC_LOCK": {}, "CAP_IPC_OWNER": {}, "CAP_SYS_MODULE": {}, "CAP_SYS_RAWIO": {},
	"CAP_SYS_CHROOT": {}, "CAP_SYS_PTRACE": {}, "CAP_SYS_PACCT": {}, "CAP_SYS_ADMIN": {}, "CAP_SYS_BOOT": {},
	"CAP_SYS_NICE": {}, "CAP_SYS_RESOURCE": {}, "CAP_SYS_TIME": {}, "CAP_SYS_TTY_CONFIG": {}, "CAP_MKNOD": {},
	"CAP_LEASE": {}, "CAP_AUDIT_WRITE": {}, "CAP_AUDIT_CONTROL": {}, "CAP_SETFCAP": {}, "CAP_MAC_OVERRIDE": {},
	"CAP_MAC_ADMIN": {}, "CAP_SYSLOG": {}, "CAP_WAKE_ALARM": {}, "CAP_BLOCK_SUSPEND": {}, "CAP_AUDIT_READ": {},
	"CAP_PERFMON": {}, "CAP_BPF": {}, "CAP_CHECKPOINT_RESTORE": {},
}

func IsKnownCapability(name string) bool {
	name = strings.ToUpper(strings.TrimSpace(name))
	if name == "ALL" {
		return true
	}
	_, ok := knownCapabilities[name]
	return ok
}

func pathHasParentEscape(path string) bool {
	for _, part := range strings.Split(path, string(filepath.Separator)) {
		if part == ".." {
			return true
		}
	}
	return false
}
