package config

import (
	"strings"
	"testing"

	"sandbox/demo/network"
)

func TestConfig_ValidationAndParity(t *testing.T) {
	tests := []struct {
		name        string
		inputConfig Config
		wantErr     bool
		errContains string
	}{
		{
			name: "Valid: Standard host execution",
			inputConfig: Config{
				NetworkMode: network.Host,
				Command:     []string{"echo", "hello-world"},
			},
			wantErr: false,
		},
		{
			name: "Valid: Isolated network with flag arguments in command",
			inputConfig: Config{
				NetworkMode: network.None,
				Command:     []string{"pytest", "-v", "--tb=short"},
			},
			wantErr: false,
		},
		{
			name: "Error: Uninitialized or unsupported network mode",
			inputConfig: Config{
				NetworkMode: network.NetworkMode("malicious-mode"),
				Command:     []string{"ls"},
			},
			wantErr:     true,
			errContains: "invalid network mode",
		},
		{
			name: "Error: Empty network mode string",
			inputConfig: Config{
				NetworkMode: network.NetworkMode(""),
				Command:     []string{"ls"},
			},
			wantErr:     true,
			errContains: "invalid network mode",
		},
		{
			name: "Error: Completely empty command slice",
			inputConfig: Config{
				NetworkMode: network.Bridge,
				Command:     []string{},
			},
			wantErr:     true,
			errContains: "command slice cannot be empty",
		},
		{
			name: "Error: Command slice containing empty strings",
			inputConfig: Config{
				NetworkMode: network.Host,
				Command:     []string{"python", "", "script.py"},
			},
			wantErr:     true,
			errContains: "is empty or only whitespace",
		},
		{
			name: "Error: Command slice containing only whitespace",
			inputConfig: Config{
				NetworkMode: network.Host,
				Command:     []string{"   "},
			},
			wantErr:     true,
			errContains: "is empty or only whitespace",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.inputConfig.Validate()

			if (err != nil) != tt.wantErr {
				t.Fatalf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}

			if tt.wantErr && !strings.Contains(err.Error(), tt.errContains) {
				t.Errorf("Validate() error msg = %q, expected to contain %q", err.Error(), tt.errContains)
			}
		})
	}
}
