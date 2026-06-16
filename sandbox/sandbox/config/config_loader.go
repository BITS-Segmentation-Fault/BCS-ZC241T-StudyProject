package config

import (
	"fmt"
	"io"
	"os"

	"gopkg.in/yaml.v3"
)

// Read a YAML file at the given path and returns a parsed Config.
func LoadConfig(path string) (*Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("value_error: cannot open config file %q: %v", path, err)
	}
	defer f.Close()

	return LoadConfigFromReader(f)
}

// Decode a YAML config from the provided reader.
func LoadConfigFromReader(r io.Reader) (*Config, error) {
	cfg := DefaultConfig()

	decoder := yaml.NewDecoder(r)
	decoder.KnownFields(true)

	if err := decoder.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("value_error: config parse failure: %v", err)
	}

	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	return &cfg, nil
}
