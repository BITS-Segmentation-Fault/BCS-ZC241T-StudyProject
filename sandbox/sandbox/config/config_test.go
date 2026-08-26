package config

import (
	"strings"
	"testing"

	"sandbox/sandbox/network"
)

func validConfig() Config {
	c := DefaultConfig()
	c.Command = []string{"/bin/echo", ""}
	return c
}

func TestDefaultConfig(t *testing.T) {
	c := DefaultConfig()
	if c.ReadOnlyRoot != true || c.BlockedSyscallAction != ActionKill || c.NetworkMode != network.None || c.WorkingDir != "/" {
		t.Fatalf("unexpected security defaults: %+v", c)
	}
	if len(c.EnvVars) != 1 || c.EnvVars[0] != "PATH=/bin:/usr/bin" || c.CPULimitPercent != 0 || c.MemoryLimitGB != 0 || c.MaxProcesses != 0 || c.FileSizeLimitMB != 100 {
		t.Fatalf("unexpected resource/environment defaults: %+v", c)
	}
	if c.RootFSSource != "" || len(c.DropCapabilities) != 1 || c.DropCapabilities[0] != "ALL" {
		t.Fatalf("unexpected rootfs/capability defaults: %+v", c)
	}
}

func TestCommandValidation(t *testing.T) {
	tests := []struct {
		name    string
		command []string
		want    string
	}{
		{"missing", nil, "at least one"},
		{"empty executable", []string{""}, "executable"},
		{"whitespace executable", []string{"  "}, "executable"},
		{"nul executable", []string{"echo\x00"}, "NUL"},
		{"nul argument", []string{"echo", "a\x00b"}, "NUL"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := validConfig()
			c.Command = tt.command
			if err := c.Validate(); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Validate() = %v, want %q", err, tt.want)
			}
		})
	}
	c := validConfig()
	if err := c.Validate(); err != nil {
		t.Fatalf("empty argument rejected: %v", err)
	}
}

func TestValidatePolicies(t *testing.T) {
	tests := []struct {
		name   string
		change func(*Config)
		want   string
	}{
		{"unknown action", func(c *Config) { c.BlockedSyscallAction = "log" }, "blocked_syscall_action"},
		{"unknown capability", func(c *Config) { c.DropCapabilities = []string{"CAP_NOPE"} }, "unknown capability"},
		{"mixed all", func(c *Config) { c.DropCapabilities = []string{"ALL", "CAP_CHOWN"} }, "ALL"},
		{"negative file size", func(c *Config) { c.FileSizeLimitMB = -1 }, "file_size_limit_mb"},
		{"negative cpu", func(c *Config) { c.CPULimitPercent = -1 }, "cpu_limit_percent"},
		{"cpu above maximum", func(c *Config) { c.CPULimitPercent = 101 }, "cpu_limit_percent"},
		{"negative memory", func(c *Config) { c.MemoryLimitGB = -1 }, "memory_limit_gb"},
		{"negative processes", func(c *Config) { c.MaxProcesses = -1 }, "max_processes"},
		{"invalid DNS", func(c *Config) { c.DNSServers = []string{"not-an-ip"} }, "dns_servers"},
		{"managed root writable", func(c *Config) { c.ReadOnlyRoot = false }, "managed rootfs"},
		{"root bind", func(c *Config) { c.BindMounts = []BindMount{{HostPath: "/tmp", ContainerPath: "/"}} }, "cannot be root"},
		{"duplicate bind target", func(c *Config) {
			c.BindMounts = []BindMount{{HostPath: "/tmp", ContainerPath: "/mnt/x"}, {HostPath: "/var", ContainerPath: "/mnt//x"}}
		}, "duplicate"},
		{"overlapping bind target", func(c *Config) {
			c.BindMounts = []BindMount{{HostPath: "/tmp", ContainerPath: "/mnt"}, {HostPath: "/var", ContainerPath: "/mnt/sub"}}
		}, "overlapping"},
		{"proc bind target", func(c *Config) { c.BindMounts = []BindMount{{HostPath: "/tmp", ContainerPath: "/proc/log"}} }, "reserved for proc"},
		{"DNS bind target", func(c *Config) {
			c.DNSServers = []string{"1.1.1.1"}
			c.BindMounts = []BindMount{{HostPath: "/tmp", ContainerPath: "/etc/resolv.conf"}}
		}, "conflicts"},
		{"near proc bind target", func(c *Config) { c.BindMounts = []BindMount{{HostPath: "/tmp", ContainerPath: "/processor"}} }, ""},
		{"near DNS bind target", func(c *Config) {
			c.DNSServers = []string{"1.1.1.1"}
			c.BindMounts = []BindMount{{HostPath: "/tmp", ContainerPath: "/etc/resolv.conf.d"}}
		}, ""},
		{"traversal", func(c *Config) { c.WorkingDir = "/a/../b" }, "cannot contain .."},
		{"empty working directory", func(c *Config) { c.WorkingDir = "" }, "working_dir cannot be empty"},
		{"relative bind source", func(c *Config) { c.BindMounts = []BindMount{{HostPath: "tmp", ContainerPath: "/mnt"}} }, "bind_mount host_path"},
		{"NUL bind source", func(c *Config) { c.BindMounts = []BindMount{{HostPath: "/tmp\x00host", ContainerPath: "/mnt"}} }, "bind_mount host_path"},
		{"host bind traversal", func(c *Config) { c.BindMounts = []BindMount{{HostPath: "/tmp/../host", ContainerPath: "/mnt"}} }, "bind_mount host_path"},
		{"relative bind target", func(c *Config) { c.BindMounts = []BindMount{{HostPath: "/tmp", ContainerPath: "mnt"}} }, "bind_mount container_path"},
		{"NUL bind target", func(c *Config) { c.BindMounts = []BindMount{{HostPath: "/tmp", ContainerPath: "/mnt\x00target"}} }, "bind_mount container_path"},
		{"invalid bridge", func(c *Config) { c.NetworkMode = network.Bridge; c.BridgeConfig.MTU = 1 }, "bridge config"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := validConfig()
			tt.change(&c)
			err := c.Validate()
			if tt.want != "" && (err == nil || !strings.Contains(err.Error(), tt.want)) {
				t.Fatalf("Validate() = %v, want %q", err, tt.want)
			}
			if tt.want == "" && err != nil {
				t.Fatalf("Validate() = %v, want valid configuration", err)
			}
		})
	}
}

func TestValidateEnvironment(t *testing.T) {
	for _, entry := range []string{"=x", "bad-name=x", "PATH", "A\x00=x"} {
		c := validConfig()
		c.EnvVars = []string{entry}
		if err := c.Validate(); err == nil {
			t.Errorf("Validate() accepted %q", entry)
		}
	}
	c := validConfig()
	c.EnvVars = []string{"A=1", "A=2"}
	if err := c.Validate(); err == nil {
		t.Error("duplicate environment key accepted")
	}
	c = validConfig()
	c.EnvWhitelist = []string{"A", "A"}
	if err := c.Validate(); err == nil {
		t.Error("duplicate whitelist key accepted")
	}
}

func TestEnvironmentMerge(t *testing.T) {
	c := validConfig()
	c.EnvVars = []string{"PATH=/custom", "A=explicit"}
	c.EnvWhitelist = []string{"A", "B"}
	got := c.Environment([]string{"PATH=/host", "A=host", "B=host", "C=secret"})
	want := []string{"PATH=/custom", "A=explicit", "B=host"}
	if strings.Join(got, "\x00") != strings.Join(want, "\x00") {
		t.Fatalf("Environment() = %#v, want %#v", got, want)
	}
}

func TestCapabilityLookup(t *testing.T) {
	if n, ok := CapabilityNumber("cap_net_admin"); !ok || n != 12 {
		t.Fatalf("CapabilityNumber() = %d, %v", n, ok)
	}
	if !isKnownCapability(" all ") || isKnownCapability("CAP_UNKNOWN") {
		t.Fatal("capability validation mismatch")
	}
}
