package main

import (
	"flag"
	"os"
	"sandbox/demo/child"
	"sandbox/demo/config"
	"sandbox/demo/parent"
	"strings"
)

func main() {
	isChild := flag.Bool("child", false, "Internal use only - identifies the child process container track")
	envWhitelistStr := flag.String("env-whitelist", "PATH,TERM", "Comma-separated list of allowed host variables")
	flag.Parse()

	// 1. Generate a valid baseline config from config.go
	cfg := config.DefaultConfig()

	// 2. Use the flag variable to split the comma-separated string into the slice
	if *envWhitelistStr != "" {
		cfg.EnvWhitelist = strings.Split(*envWhitelistStr, ",")
	}

	// 3. Capture remaining non-flag arguments as the target execution command
	cfg.Command = flag.Args()
	if len(cfg.Command) == 0 {
		cfg.Command = []string{"/bin/payload"}
	}

	// 4. Route target track execution depending on context flag states
	if *isChild {
		rc := child.Child(cfg, 0, 0, 0, 0)
		os.Exit(rc)
	} else {
		rc := parent.Parent(cfg)
		os.Exit(rc)
	}
}
