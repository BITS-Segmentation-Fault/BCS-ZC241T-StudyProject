package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"

	"sandbox/sandbox/config"
	"sandbox/sandbox/network"
	"sandbox/sandbox/security"
)

type cliValues struct {
	configFile      *string
	networkMode     *string
	bridgeSubnet    *string
	bridgeGateway   *string
	bridgeContainer *string
	envWhitelist    *string
	fileSizeLimit   *int
}

type parsedCLI struct {
	values cliValues
	seen   map[string]bool
	args   []string
}

var cliFlagTakesValue = map[string]bool{
	"config": true, "network-mode": true, "bridge-subnet": true,
	"bridge-gateway": true, "bridge-container-ip": true,
	"env-whitelist": true, "file-size-limit": true,
}

func registerFlags(fs *flag.FlagSet, defaults config.Config) cliValues {
	return cliValues{
		configFile:      fs.String("config", "", "Load configuration from a YAML file"),
		networkMode:     fs.String("network-mode", string(defaults.NetworkMode), "Network namespace mode"),
		bridgeSubnet:    fs.String("bridge-subnet", defaults.BridgeConfig.Subnet, "Bridge subnet CIDR"),
		bridgeGateway:   fs.String("bridge-gateway", defaults.BridgeConfig.GatewayIP, "Bridge gateway address"),
		bridgeContainer: fs.String("bridge-container-ip", defaults.BridgeConfig.ContainerIP, "Container bridge address"),
		envWhitelist:    fs.String("env-whitelist", strings.Join(defaults.EnvWhitelist, ","), "Host environment keys to copy"),
		fileSizeLimit:   fs.Int("file-size-limit", defaults.FileSizeLimitMB, "Per-file size limit in MiB"),
	}
}

func parseCLI(argv []string, defaults config.Config) (parsedCLI, error) {
	seen, err := validateFlagTokens(argv)
	if err != nil {
		return parsedCLI{}, err
	}
	fs := flag.NewFlagSet("sandbox", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	values := registerFlags(fs, defaults)
	if err := fs.Parse(argv); err != nil {
		return parsedCLI{}, err
	}
	return parsedCLI{values: values, seen: seen, args: append([]string(nil), fs.Args()...)}, nil
}

func validateFlagTokens(argv []string) (map[string]bool, error) {
	seen := make(map[string]bool)
	for i := 0; i < len(argv); i++ {
		arg := argv[i]
		if arg == "--" || !strings.HasPrefix(arg, "-") || arg == "-" {
			break
		}
		nameValue := strings.TrimLeft(arg, "-")
		name, value, hasValue := strings.Cut(nameValue, "=")
		if name == "" {
			return nil, errors.New("invalid empty option")
		}
		if seen[name] {
			return nil, fmt.Errorf("option --%s was specified more than once", name)
		}
		seen[name] = true
		if !cliFlagTakesValue[name] {
			continue
		}
		if hasValue {
			if value == "" {
				return nil, fmt.Errorf("option --%s requires a value", name)
			}
			continue
		}
		if i+1 >= len(argv) {
			return nil, fmt.Errorf("option --%s requires a value", name)
		}
		i++
	}
	return seen, nil
}

func ParseArgs(argv []string) (config.Config, error) {
	discovered, err := parseCLI(argv, config.DefaultConfig())
	if err != nil {
		return config.Config{}, err
	}
	cfg := config.DefaultConfig()
	if *discovered.values.configFile != "" {
		loaded, err := config.LoadConfig(*discovered.values.configFile)
		if err != nil {
			return config.Config{}, fmt.Errorf("config: %w", err)
		}
		cfg = *loaded
	}
	parsed, err := parseCLI(argv, cfg)
	if err != nil {
		return config.Config{}, err
	}
	values := parsed.values
	if parsed.seen["network-mode"] {
		cfg.NetworkMode = network.NetworkMode(*values.networkMode)
	}
	if parsed.seen["bridge-subnet"] {
		cfg.BridgeConfig.Subnet = *values.bridgeSubnet
	}
	if parsed.seen["bridge-gateway"] {
		cfg.BridgeConfig.GatewayIP = *values.bridgeGateway
	}
	if parsed.seen["bridge-container-ip"] {
		cfg.BridgeConfig.ContainerIP = *values.bridgeContainer
	}
	if parsed.seen["env-whitelist"] {
		cfg.EnvWhitelist = splitCSV(*values.envWhitelist)
	}
	if parsed.seen["file-size-limit"] {
		cfg.FileSizeLimitMB = *values.fileSizeLimit
	}
	if len(parsed.args) > 0 {
		if len(cfg.Command) > 0 {
			return config.Config{}, errors.New("value_error: command was supplied both by configuration and CLI")
		}
		cfg.Command = append([]string(nil), parsed.args...)
	}
	if err := cfg.Validate(); err != nil {
		return config.Config{}, err
	}
	if err := security.ValidateSyscallNames(cfg.BlockedSyscalls); err != nil {
		return config.Config{}, fmt.Errorf("value_error: %w", err)
	}
	return cfg, nil
}

func splitCSV(value string) []string {
	var result []string
	for _, part := range strings.Split(value, ",") {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}
