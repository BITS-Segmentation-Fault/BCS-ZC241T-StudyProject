package config

import (
	"errors"
	"strings"

	"sandbox/demo/network"
)

// StorageConfig defines the three-tiered progressive storage allocation parameters.
type StorageConfig struct {
	InitialLimitMB    int    `yaml:"initial_limit_mb"`    // Ceiling mapped to Cur in Setrlimit
	AbsoluteMaximumMB int    `yaml:"absolute_maximum_mb"` // Ceiling mapped to Max in Setrlimit
	ExpansionPolicy   string `yaml:"expansion_policy"`    // "none", "automatic", or "manual"
	IncrementStepMB   int    `yaml:"increment_step_mb"`   // Buffer step added per breach threshold
}

// Config represents the full structural runtime parameters for the sandbox container.
type Config struct {
	NetworkMode  network.NetworkMode `yaml:"network_mode"`
	Command      []string            `yaml:"command"`
	EnvWhitelist []string            `yaml:"env_whitelist"` // Tier 1: User-defined allowed host variables
	Storage      StorageConfig       `yaml:"storage"`       // Tier 1/2: Storage isolation constraints
}

// DefaultConfig provides standard, secure baseline parameters for the runtime environment.
func DefaultConfig() Config {
	return Config{
		NetworkMode:  network.Host,
		EnvWhitelist: []string{},
		Storage: StorageConfig{
			InitialLimitMB:    100,
			AbsoluteMaximumMB: 500,
			ExpansionPolicy:   "automatic",
			IncrementStepMB:   50,
		},
	}
}

// Validate reviews the structural sanity of runtime configurations to protect the host system.
func (c *Config) Validate() error {
	if !c.NetworkMode.IsValid() {
		return errors.New("value_error: invalid network mode configuration state")
	}

	if len(c.Command) == 0 {
		return errors.New("value_error: command slice cannot be empty")
	}

	for _, arg := range c.Command {
		if strings.TrimSpace(arg) == "" {
			return errors.New("value_error: command array element is empty or only whitespace")
		}
	}

	// Structural Validation for the Three-Tiered Storage Matrix
	s := c.Storage
	if s.InitialLimitMB <= 0 || s.AbsoluteMaximumMB <= 0 {
		return errors.New("value_error: storage limit values must be positive integers greater than zero")
	}
	if s.InitialLimitMB > s.AbsoluteMaximumMB {
		return errors.New("value_error: initial storage allocation cannot cross absolute maximum boundary")
	}

	policy := strings.ToLower(s.ExpansionPolicy)
	if policy != "none" && policy != "automatic" && policy != "manual" {
		return errors.New("value_error: expansion_policy must be explicitly set to 'none', 'automatic', or 'manual'")
	}

	if (policy == "automatic" || policy == "manual") && s.IncrementStepMB <= 0 {
		return errors.New("value_error: incremental storage allocation step must be greater than zero when expansion is enabled")
	}

	return nil
}
