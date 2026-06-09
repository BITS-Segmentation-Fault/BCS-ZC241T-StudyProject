package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"

	"sandbox/demo/config"
	"sandbox/demo/network"
)

type Args struct {
	Config  config.Config
	Verbose bool
}

func ParseArgs(argv []string) (Args, error) {
	fs := flag.NewFlagSet("sandbox", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	// Fetch secure standard baselines
	defaultCfg := config.DefaultConfig()

	networkModeStr := fs.String("network-mode", string(defaultCfg.NetworkMode), "Network namespace isolation mode")
	verbose := fs.Bool("verbose", false, "Enable microsecond diagnostic trace tracking records")

	// Command line configuration bindings for resource policies
	envWhitelistStr := fs.String("env-whitelist", "", "Comma-separated keys of allowed host environment variables")
	initialStorage := fs.Int("storage-initial", defaultCfg.Storage.InitialLimitMB, "Initial file storage limit boundary in Megabytes")
	maxStorage := fs.Int("storage-max", defaultCfg.Storage.AbsoluteMaximumMB, "Absolute hard stop file storage capacity limit in Megabytes")
	storagePolicy := fs.String("storage-policy", defaultCfg.Storage.ExpansionPolicy, "Threshold breach mitigation rule policy behavior")
	storageStep := fs.Int("storage-step", defaultCfg.Storage.IncrementStepMB, "Capacity allocation block added upon limit violation triggers")

	if err := fs.Parse(argv); err != nil {
		return Args{}, err
	}

	command := fs.Args()
	if len(command) == 0 {
		return Args{}, errors.New("error: the following arguments are required: command")
	}

	for _, arg := range command {
		if strings.TrimSpace(arg) == "" {
			return Args{}, errors.New("value_error: command argument is empty or only whitespace")
		}
	}

	netMode := network.NetworkMode(*networkModeStr)
	if !netMode.IsValid() {
		return Args{}, fmt.Errorf("value_error: %q is not a valid NetworkMode", *networkModeStr)
	}

	// Construct safe custom environment array fields
	var whitelistSlice []string
	if *envWhitelistStr != "" {
		parts := strings.Split(*envWhitelistStr, ",")
		for _, part := range parts {
			trimmed := strings.TrimSpace(part)
			if trimmed != "" {
				whitelistSlice = append(whitelistSlice, trimmed)
			}
		}
	}

	// Populate the comprehensive parsed Config runtime state
	cfg := config.Config{
		NetworkMode:  netMode,
		Command:      command,
		EnvWhitelist: whitelistSlice,
		Storage: config.StorageConfig{
			InitialLimitMB:    *initialStorage,
			AbsoluteMaximumMB: *maxStorage,
			ExpansionPolicy:   strings.ToLower(*storagePolicy),
			IncrementStepMB:   *storageStep,
		},
	}

	// Trigger the schema-wide verification guard logic
	if err := cfg.Validate(); err != nil {
		return Args{}, err
	}

	return Args{
		Config:  cfg,
		Verbose: *verbose,
	}, nil
}
