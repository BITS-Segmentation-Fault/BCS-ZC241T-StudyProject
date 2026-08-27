package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseArgs(t *testing.T) {
	got, err := parseArgs([]string{"--network-mode=host", "/bin/echo", ""})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(got.Command, "\x00") != "/bin/echo\x00" || string(got.NetworkMode) != "host" {
		t.Fatalf("unexpected args: %+v", got)
	}
	if got.CPULimitPercent != 0 {
		t.Fatalf("CPU default = %d", got.CPULimitPercent)
	}
	if got.Interactive {
		t.Fatal("interactive default = true, want false")
	}
}

func TestParseArgsInteractiveFlags(t *testing.T) {
	for _, test := range []struct {
		name string
		args []string
		want bool
	}{
		{name: "long", args: []string{"--interactive", "/bin/echo"}, want: true},
		{name: "short", args: []string{"-i", "/bin/echo"}, want: true},
		{name: "explicit false", args: []string{"--interactive=false", "/bin/echo"}, want: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := parseArgs(test.args)
			if err != nil {
				t.Fatal(err)
			}
			if got.Interactive != test.want {
				t.Fatalf("Interactive = %v, want %v", got.Interactive, test.want)
			}
		})
	}
}

func TestParseArgsConfigAndOverrides(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sandbox.yaml")
	if err := os.WriteFile(path, []byte("command: [/bin/echo, from-config]\nnetwork_mode: host\nfile_size_limit_mb: 4\n"), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := parseArgs([]string{"--network-mode", "host", "--config", path, "--file-size-limit", "8", "--env-whitelist", "ALLOWED"})
	if err != nil {
		t.Fatal(err)
	}
	if string(got.NetworkMode) != "host" || got.FileSizeLimitMB != 8 || strings.Join(got.EnvWhitelist, ",") != "ALLOWED" {
		t.Fatalf("config/override lost: %+v", got)
	}
}

func TestParseArgsInteractiveFalseOverridesYAML(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sandbox.yaml")
	if err := os.WriteFile(path, []byte("command: [/bin/echo, from-config]\ninteractive: true\n"), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := parseArgs([]string{"--config", path, "--interactive=false"})
	if err != nil {
		t.Fatal(err)
	}
	if got.Interactive {
		t.Fatal("CLI false did not override YAML interactive=true")
	}
}

func TestParseArgsRejectsInvalidPublicSyntax(t *testing.T) {
	for _, argv := range [][]string{{}, {"--unknown", "/bin/echo"}, {"--file-size-limit"}} {
		if _, err := parseArgs(argv); err == nil {
			t.Errorf("ParseArgs(%q) accepted invalid input", argv)
		}
	}
}

func TestParseArgsStopsFlagsAtDoubleDash(t *testing.T) {
	got, err := parseArgs([]string{"--network-mode", "none", "--", "/bin/echo", "--file-size-limit", ""})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Command) != 3 || got.Command[1] != "--file-size-limit" {
		t.Fatalf("command parsing changed: %#v", got.Command)
	}
}
