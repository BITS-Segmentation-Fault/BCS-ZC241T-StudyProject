package config

import (
	"errors"
	"fmt"
	"strings"

	"sandbox/demo/network"
)

type Config struct {
	NetworkMode network.NetworkMode
	Command     []string
}

func (c Config) Validate() error {
	if !c.NetworkMode.IsValid() {
		return fmt.Errorf("config_error: invalid network mode %q", c.NetworkMode)
	}

	if len(c.Command) == 0 {
		return errors.New("config_error: command slice cannot be empty")
	}

	for i, cmd := range c.Command {
		if strings.TrimSpace(cmd) == "" {
			return fmt.Errorf("config_error: command argument at index %d is empty or only whitespace", i)
		}
	}

	return nil
}
