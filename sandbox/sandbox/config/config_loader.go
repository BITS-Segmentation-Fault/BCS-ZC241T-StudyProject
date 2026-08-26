package config

import (
	"bytes"
	"fmt"
	"io"
	"os"

	"gopkg.in/yaml.v3"
)

const maxConfigBytes = 1 << 20

func LoadConfig(path string) (*Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("value_error: cannot open config file %q: %w", path, err)
	}
	defer f.Close()
	return LoadConfigFromReader(f)
}

func LoadConfigFromReader(r io.Reader) (*Config, error) {
	data, err := io.ReadAll(io.LimitReader(r, maxConfigBytes+1))
	if err != nil {
		return nil, fmt.Errorf("value_error: read config: %w", err)
	}
	if len(data) > maxConfigBytes {
		return nil, fmt.Errorf("value_error: config exceeds %d-byte limit", maxConfigBytes)
	}
	cfg := DefaultConfig()
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("value_error: config parse failure: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return nil, fmt.Errorf("value_error: config contains more than one YAML document")
		}
		return nil, fmt.Errorf("value_error: trailing config data: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}
