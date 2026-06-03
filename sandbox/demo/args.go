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

	networkModeStr := fs.String("network-mode", string(network.Host), "")
	verbose := fs.Bool("verbose", false, "")

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

	cfg := config.Config{
		NetworkMode: netMode,
		Command:     command,
	}

	return Args{
		Config:  cfg,
		Verbose: *verbose,
	}, nil
}
