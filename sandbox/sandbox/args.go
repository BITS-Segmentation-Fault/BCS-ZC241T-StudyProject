package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"

	"sandbox/sandbox/config"
	"sandbox/sandbox/network"
)

type Args struct {
	Config  config.Config
	Verbose bool
}

func ParseArgs(argv []string) (Args, error) {
	// Early parse to detect -config before the full flag set processes
	earlyFS := flag.NewFlagSet("config-detect", flag.ContinueOnError)
	earlyFS.SetOutput(io.Discard)
	configPath := earlyFS.String("config", "", "")
	_ = earlyFS.Parse(argv)

	// Filter out the -config flag and its values from argv so the main flag set doesn't panic
	var cleanArgv []string
	for i := 0; i < len(argv); i++ {
		if argv[i] == "-config" || argv[i] == "--config" {
			i++ // Skip the flag's value argument
			continue
		}
		if strings.HasPrefix(argv[i], "-config=") || strings.HasPrefix(argv[i], "--config=") {
			continue // Skip combined strings like --config=path
		}
		cleanArgv = append(cleanArgv, argv[i])
	}

	var baseCfg config.Config
	if *configPath != "" {
		loaded, err := config.LoadConfig(*configPath)
		if err != nil {
			return Args{}, fmt.Errorf("config: %v", err)
		}
		baseCfg = *loaded
	} else {
		baseCfg = config.DefaultConfig()
	}

	// Main flag set with defaults from YAML or stock defaults
	fs := flag.NewFlagSet("sandbox", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	verbose := fs.Bool("verbose", false, "Enable microsecond diagnostic trace tracking records")
	networkModeStr := fs.String("network-mode", string(baseCfg.NetworkMode), "Network namespace isolation mode")
	bridgeSubnet := fs.String("bridge-subnet", baseCfg.BridgeConfig.Subnet, "Bridge network subnet CIDR")
	bridgeGateway := fs.String("bridge-gateway", baseCfg.BridgeConfig.GatewayIP, "Bridge gateway IP address")
	bridgeContainerIP := fs.String("bridge-container-ip", baseCfg.BridgeConfig.ContainerIP, "Container bridge interface IP address")
	envWhitelistStr := fs.String("env-whitelist", strings.Join(baseCfg.EnvWhitelist, ","), "Comma-separated keys of allowed host environment variables")
	initialStorage := fs.Int("storage-initial", baseCfg.Storage.InitialLimitMB, "Initial file storage limit boundary in Megabytes")
	maxStorage := fs.Int("storage-max", baseCfg.Storage.AbsoluteMaximumMB, "Absolute hard stop file storage capacity limit in Megabytes")
	storagePolicy := fs.String("storage-policy", baseCfg.Storage.ExpansionPolicy, "Threshold breach mitigation rule policy behavior")
	storageStep := fs.Int("storage-step", baseCfg.Storage.IncrementStepMB, "Capacity allocation block added upon limit violation triggers")

	// Use cleanArgv here instead of original unstripped argv
	if err := fs.Parse(cleanArgv); err != nil {
		return Args{}, err
	}

	// Start from base config and overlay CLI-provided values
	cfg := baseCfg

	// Network mode override
	if *networkModeStr != string(baseCfg.NetworkMode) {
		netMode := network.NetworkMode(*networkModeStr)
		if !netMode.IsValid() {
			return Args{}, fmt.Errorf("value_error: %q is not a valid NetworkMode", *networkModeStr)
		}
		cfg.NetworkMode = netMode
	}

	// Bridge config overrides
	if *bridgeSubnet != network.DefaultBridgeConfig().Subnet {
		cfg.BridgeConfig.Subnet = *bridgeSubnet
	}
	if *bridgeGateway != network.DefaultBridgeConfig().GatewayIP {
		cfg.BridgeConfig.GatewayIP = *bridgeGateway
	}
	if *bridgeContainerIP != network.DefaultBridgeConfig().ContainerIP {
		cfg.BridgeConfig.ContainerIP = *bridgeContainerIP
	}

	// Environment whitelist override
	if *envWhitelistStr != "" {
		parts := strings.Split(*envWhitelistStr, ",")
		var whitelist []string
		for _, part := range parts {
			trimmed := strings.TrimSpace(part)
			if trimmed != "" {
				whitelist = append(whitelist, trimmed)
			}
		}
		if len(whitelist) > 0 {
			cfg.EnvWhitelist = whitelist
		}
	}

	// Storage overrides
	if *initialStorage != config.DefaultConfig().Storage.InitialLimitMB {
		cfg.Storage.InitialLimitMB = *initialStorage
	}
	if *maxStorage != config.DefaultConfig().Storage.AbsoluteMaximumMB {
		cfg.Storage.AbsoluteMaximumMB = *maxStorage
	}
	if *storagePolicy != config.DefaultConfig().Storage.ExpansionPolicy {
		cfg.Storage.ExpansionPolicy = strings.ToLower(*storagePolicy)
	}
	if *storageStep != config.DefaultConfig().Storage.IncrementStepMB {
		cfg.Storage.IncrementStepMB = *storageStep
	}

	// Positional args override command
	command := fs.Args()
	if len(command) > 0 {
		for _, arg := range command {
			if strings.TrimSpace(arg) == "" {
				return Args{}, errors.New("value_error: command argument is empty or only whitespace")
			}
		}
		cfg.Command = command
	}

	// Validate merged result
	if err := cfg.Validate(); err != nil {
		return Args{}, err
	}

	return Args{
		Config:  cfg,
		Verbose: *verbose,
	}, nil
}
