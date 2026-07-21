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

type Args struct {
	Config  config.Config
	Verbose bool
}

type cliValues struct {
	configPath      *string
	verbose         *bool
	networkMode     *string
	bridgeSubnet    *string
	bridgeGateway   *string
	bridgeContainer *string
	envWhitelist    *string
	initialStorage  *int
	maximumStorage  *int
	storagePolicy   *string
	storageStep     *int
}

type parsedCLI struct {
	values cliValues
	seen   map[string]bool
	args   []string
}

var cliFlagTakesValue = map[string]bool{
	"config":              true,
	"network-mode":        true,
	"bridge-subnet":       true,
	"bridge-gateway":      true,
	"bridge-container-ip": true,
	"env-whitelist":       true,
	"storage-initial":     true,
	"storage-max":         true,
	"storage-policy":      true,
	"storage-step":        true,
}

func registerFlags(fs *flag.FlagSet, defaults config.Config) cliValues {
	return cliValues{
		configPath:      fs.String("config", "", "Load configuration from a YAML file"),
		verbose:         fs.Bool("verbose", false, "Enable diagnostic logging"),
		networkMode:     fs.String("network-mode", string(defaults.NetworkMode), "Network namespace mode"),
		bridgeSubnet:    fs.String("bridge-subnet", defaults.BridgeConfig.Subnet, "Bridge subnet CIDR"),
		bridgeGateway:   fs.String("bridge-gateway", defaults.BridgeConfig.GatewayIP, "Bridge gateway address"),
		bridgeContainer: fs.String("bridge-container-ip", defaults.BridgeConfig.ContainerIP, "Container bridge address"),
		envWhitelist:    fs.String("env-whitelist", strings.Join(defaults.EnvWhitelist, ","), "Host environment keys to copy"),
		initialStorage:  fs.Int("storage-initial", defaults.Storage.InitialLimitMB, "Initial file-size limit in MiB"),
		maximumStorage:  fs.Int("storage-max", defaults.Storage.AbsoluteMaximumMB, "Maximum file-size limit in MiB"),
		storagePolicy:   fs.String("storage-policy", defaults.Storage.ExpansionPolicy, "Deprecated storage expansion policy"),
		storageStep:     fs.Int("storage-step", defaults.Storage.IncrementStepMB, "Deprecated storage expansion step"),
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
			return nil, fmt.Errorf("invalid empty option")
		}
		if seen[name] {
			return nil, fmt.Errorf("option --%s was specified more than once", name)
		}
		seen[name] = true

		_, known := cliFlagTakesValue[name]
		if !known {
			if name == "verbose" {
				if hasValue && value != "true" && value != "false" {
					return nil, fmt.Errorf("invalid boolean value for --verbose")
				}
				continue
			}
			// Let flag.FlagSet produce its standard unknown-option diagnostic.
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

func ParseArgs(argv []string) (Args, error) {
	// Pass one uses the built-in defaults only to discover --config and validate
	// the complete public option stream. It is intentionally order-independent.
	discovered, err := parseCLI(argv, config.DefaultConfig())
	if err != nil {
		return Args{}, err
	}

	baseCfg := config.DefaultConfig()
	if *discovered.values.configPath != "" {
		loaded, err := config.LoadConfig(*discovered.values.configPath)
		if err != nil {
			return Args{}, fmt.Errorf("config: %v", err)
		}
		baseCfg = *loaded
	}

	// Pass two uses YAML values as defaults and applies only flags explicitly
	// supplied by the caller. This preserves values that were not overridden.
	parsed, err := parseCLI(argv, baseCfg)
	if err != nil {
		return Args{}, err
	}
	values := parsed.values
	cfg := baseCfg

	if parsed.seen["network-mode"] {
		cfg.NetworkMode = network.NetworkMode(*values.networkMode)
		if !cfg.NetworkMode.IsValid() {
			_, err := network.ParseNetworkMode(*values.networkMode)
			return Args{}, err
		}
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
	if parsed.seen["storage-initial"] {
		cfg.Storage.InitialLimitMB = *values.initialStorage
	}
	if parsed.seen["storage-max"] {
		cfg.Storage.AbsoluteMaximumMB = *values.maximumStorage
	}
	if parsed.seen["storage-policy"] {
		cfg.Storage.ExpansionPolicy = strings.ToLower(*values.storagePolicy)
	}
	if parsed.seen["storage-step"] {
		cfg.Storage.IncrementStepMB = *values.storageStep
	}

	if len(parsed.args) > 0 {
		if cfg.BinaryPath != "" || len(cfg.Args) > 0 || len(cfg.Command) > 0 {
			return Args{}, errors.New("value_error: command forms are mutually exclusive")
		}
		for _, arg := range parsed.args {
			if strings.TrimSpace(arg) == "" {
				return Args{}, errors.New("value_error: command argument is empty or only whitespace")
			}
		}
		cfg.Command = append([]string(nil), parsed.args...)
	}

	if err := cfg.Validate(); err != nil {
		return Args{}, err
	}
	if err := security.ValidateSyscallNames(cfg.BlockedSyscalls); err != nil {
		return Args{}, fmt.Errorf("value_error: %v", err)
	}
	return Args{Config: cfg, Verbose: *values.verbose}, nil
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
