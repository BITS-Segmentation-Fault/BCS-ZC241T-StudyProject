package config

import (
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"regexp"
	"strings"

	"sandbox/sandbox/network"
)

type SeccompAction string

const (
	ActionKill SeccompAction = "kill"
	ActionTrap SeccompAction = "trap"
)

func (a SeccompAction) IsValid() bool { return a == ActionKill || a == ActionTrap }

type BindMount struct {
	HostPath      string `yaml:"host_path"`
	ContainerPath string `yaml:"container_path"`
	Writable      bool   `yaml:"writable"`
}

type Config struct {
	Command              []string             `yaml:"command"`
	EnvVars              []string             `yaml:"env_vars"`
	ReadOnlyRoot         bool                 `yaml:"read_only_root"`
	BlockedSyscallAction SeccompAction        `yaml:"blocked_syscall_action"`
	BlockedSyscalls      []string             `yaml:"blocked_syscalls"`
	DropCapabilities     []string             `yaml:"drop_capabilities"`
	FileSizeLimitMB      int                  `yaml:"file_size_limit_mb"`
	CPULimitPercent      int                  `yaml:"cpu_limit_percent"`
	MemoryLimitGB        int                  `yaml:"memory_limit_gb"`
	MaxProcesses         int                  `yaml:"max_processes"`
	NetworkMode          network.NetworkMode  `yaml:"network_mode"`
	BridgeConfig         network.BridgeConfig `yaml:"bridge"`
	WorkingDir           string               `yaml:"working_dir"`
	RootFSSource         string               `yaml:"rootfs_source"`
	BindMounts           []BindMount          `yaml:"bind_mounts"`
	DNSServers           []string             `yaml:"dns_servers"`
	EnvWhitelist         []string             `yaml:"env_whitelist"`
}

var environmentName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

func (c Config) Environment(hostEnvironment []string) []string {
	result := append([]string(nil), c.EnvVars...)
	seen := make(map[string]struct{}, len(result))
	for _, entry := range result {
		key, _, _ := strings.Cut(entry, "=")
		seen[key] = struct{}{}
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
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, entry)
	}
	return result
}

func DefaultConfig() Config {
	return Config{
		EnvVars:              []string{"PATH=/bin:/usr/bin"},
		ReadOnlyRoot:         true,
		BlockedSyscallAction: ActionKill,
		BlockedSyscalls:      []string{"mount", "reboot", "ptrace", "swapon", "syslog"},
		DropCapabilities:     []string{"ALL"},
		FileSizeLimitMB:      100,
		CPULimitPercent:      0,
		MemoryLimitGB:        1,
		MaxProcesses:         100,
		NetworkMode:          network.None,
		BridgeConfig:         network.DefaultBridgeConfig(),
		WorkingDir:           "/",
		RootFSSource:         "/var/lib/sandbox/rootfs",
	}
}

func (c Config) Validate() error {
	if !c.NetworkMode.IsValid() {
		return fmt.Errorf("value_error: invalid network mode %q", c.NetworkMode)
	}
	if c.NetworkMode == network.Bridge {
		if err := c.BridgeConfig.Validate(); err != nil {
			return fmt.Errorf("value_error: bridge config: %v", err)
		}
	}
	if len(c.Command) == 0 {
		return errors.New("value_error: command must contain at least one element")
	}
	if strings.TrimSpace(c.Command[0]) == "" || strings.IndexByte(c.Command[0], 0) >= 0 {
		return errors.New("value_error: command executable must be non-empty and contain no NUL")
	}
	for _, arg := range c.Command {
		if strings.IndexByte(arg, 0) >= 0 {
			return errors.New("value_error: command arguments cannot contain NUL")
		}
	}
	if !c.BlockedSyscallAction.IsValid() {
		return fmt.Errorf("value_error: invalid blocked_syscall_action %q", c.BlockedSyscallAction)
	}
	for _, name := range c.BlockedSyscalls {
		if strings.TrimSpace(name) == "" {
			return errors.New("value_error: blocked_syscalls contains empty entry")
		}
	}
	if len(c.DropCapabilities) > 1 {
		for _, name := range c.DropCapabilities {
			if strings.EqualFold(strings.TrimSpace(name), "ALL") {
				return errors.New("value_error: ALL must be the only dropped capability")
			}
		}
	}
	for _, name := range c.DropCapabilities {
		if strings.TrimSpace(name) == "" {
			return errors.New("value_error: drop_capabilities contains empty entry")
		}
		if !isKnownCapability(name) {
			return fmt.Errorf("value_error: unknown capability %q", name)
		}
	}
	if c.FileSizeLimitMB < 0 {
		return errors.New("value_error: file_size_limit_mb cannot be negative")
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
	if err := validateAbsolutePath("rootfs_source", c.RootFSSource, false); err != nil {
		return err
	}
	if err := validateAbsolutePath("working_dir", c.WorkingDir, true); err != nil {
		return err
	}
	for _, mount := range c.BindMounts {
		if err := validateAbsolutePath("bind_mount host_path", mount.HostPath, true); err != nil {
			return err
		}
		if err := validateAbsolutePath("bind_mount container_path", mount.ContainerPath, true); err != nil {
			return err
		}
		if mount.ContainerPath == "/" {
			return errors.New("value_error: bind_mount container_path cannot be root")
		}
	}
	for _, dns := range c.DNSServers {
		if strings.TrimSpace(dns) == "" || net.ParseIP(dns) == nil {
			return fmt.Errorf("value_error: dns_servers contains invalid address %q", dns)
		}
	}
	if err := validateEnvironment(c.EnvVars, "env_vars", true); err != nil {
		return err
	}
	return validateEnvironment(c.EnvWhitelist, "env_whitelist", false)
}

func validateAbsolutePath(name, value string, required bool) error {
	if value == "" && !required {
		return nil
	}
	if value == "" {
		return fmt.Errorf("value_error: %s cannot be empty", name)
	}
	if strings.IndexByte(value, 0) >= 0 || !filepath.IsAbs(value) || pathHasParentEscape(value) {
		return fmt.Errorf("value_error: %s must be absolute, contain no NUL, and cannot contain ..", name)
	}
	return nil
}

func validateEnvironment(entries []string, name string, values bool) error {
	seen := make(map[string]struct{}, len(entries))
	for _, entry := range entries {
		key := entry
		if values {
			var ok bool
			key, _, ok = strings.Cut(entry, "=")
			if !ok {
				return fmt.Errorf("value_error: %s entry %q must be KEY=VALUE", name, entry)
			}
			if strings.IndexByte(entry, 0) >= 0 {
				return fmt.Errorf("value_error: %s entry %q contains NUL", name, entry)
			}
		}
		if !environmentName.MatchString(key) {
			return fmt.Errorf("value_error: %s key %q is invalid", name, key)
		}
		if _, ok := seen[key]; ok {
			return fmt.Errorf("value_error: %s contains duplicate key %q", name, key)
		}
		seen[key] = struct{}{}
	}
	return nil
}

var capabilityNames = []string{
	"CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_DAC_READ_SEARCH", "CAP_FOWNER",
	"CAP_FSETID", "CAP_KILL", "CAP_SETGID", "CAP_SETUID",
	"CAP_SETPCAP", "CAP_LINUX_IMMUTABLE", "CAP_NET_BIND_SERVICE", "CAP_NET_BROADCAST",
	"CAP_NET_ADMIN", "CAP_NET_RAW", "CAP_IPC_LOCK", "CAP_IPC_OWNER",
	"CAP_SYS_MODULE", "CAP_SYS_RAWIO", "CAP_SYS_CHROOT", "CAP_SYS_PTRACE",
	"CAP_SYS_PACCT", "CAP_SYS_ADMIN", "CAP_SYS_BOOT", "CAP_SYS_NICE",
	"CAP_SYS_RESOURCE", "CAP_SYS_TIME", "CAP_SYS_TTY_CONFIG", "CAP_MKNOD",
	"CAP_LEASE", "CAP_AUDIT_WRITE", "CAP_AUDIT_CONTROL", "CAP_SETFCAP",
	"CAP_MAC_OVERRIDE", "CAP_MAC_ADMIN", "CAP_SYSLOG", "CAP_WAKE_ALARM",
	"CAP_BLOCK_SUSPEND", "CAP_AUDIT_READ", "CAP_PERFMON", "CAP_BPF",
	"CAP_CHECKPOINT_RESTORE",
}

func CapabilityNumber(name string) (uintptr, bool) {
	name = strings.ToUpper(strings.TrimSpace(name))
	for number, capability := range capabilityNames {
		if capability == name {
			return uintptr(number), true
		}
	}
	return 0, false
}

func isKnownCapability(name string) bool {
	if strings.EqualFold(strings.TrimSpace(name), "ALL") {
		return true
	}
	_, ok := CapabilityNumber(name)
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
