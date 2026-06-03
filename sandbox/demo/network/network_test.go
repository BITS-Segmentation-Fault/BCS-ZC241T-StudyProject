package network

import (
	"strings"
	"testing"
)

func TestNetworkMode_ParityAndEdgeCases(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		wantMode    NetworkMode
		wantErr     bool
		errContains string
	}{
		{
			name:     "Valid: host mode matching Python default",
			input:    "host",
			wantMode: Host,
			wantErr:  false,
		},
		{
			name:     "Valid: none mode",
			input:    "none",
			wantMode: None,
			wantErr:  false,
		},
		{
			name:     "Valid: bridge mode",
			input:    "bridge",
			wantMode: Bridge,
			wantErr:  false,
		},
		{
			name:        "Edge Case: Case Sensitivity (Python Enums are strict)",
			input:       "Host",
			wantMode:    "",
			wantErr:     true,
			errContains: "is not a valid NetworkMode",
		},
		{
			name:        "Edge Case: All caps input",
			input:       "HOST",
			wantMode:    "",
			wantErr:     true,
			errContains: "is not a valid NetworkMode",
		},
		{
			name:        "Edge Case: Empty String Input",
			input:       "",
			wantMode:    "",
			wantErr:     true,
			errContains: "is not a valid NetworkMode",
		},
		{
			name:        "Edge Case: Trailing or Leading Whitespace",
			input:       " host ",
			wantMode:    "",
			wantErr:     true,
			errContains: "is not a valid NetworkMode",
		},
		{
			name:        "Edge Case: Malicious/Unexpected Input",
			input:       "../invalid_mode_or_injection",
			wantMode:    "",
			wantErr:     true,
			errContains: "is not a valid NetworkMode",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotMode, err := ParseNetworkMode(tt.input)

			if (err != nil) != tt.wantErr {
				t.Fatalf("ParseNetworkMode() error = %v, wantErr %v", err, tt.wantErr)
			}

			if tt.wantErr {
				if !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("ParseNetworkMode() error = %q, expected to contain %q", err.Error(), tt.errContains)
				}
				return
			}

			if gotMode != tt.wantMode {
				t.Errorf("ParseNetworkMode() gotMode = %q, wantMode %q", gotMode, tt.wantMode)
			}
		})
	}
}
