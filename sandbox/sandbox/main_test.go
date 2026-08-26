package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseArgs(t *testing.T) {
	got, err := ParseArgs([]string{"--network-mode=host", "/bin/echo", ""})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(got.Config.Command, "\x00") != "/bin/echo\x00" || string(got.Config.NetworkMode) != "host" {
		t.Fatalf("unexpected args: %+v", got.Config)
	}
	if got.Config.CPULimitPercent != 0 {
		t.Fatalf("CPU default = %d", got.Config.CPULimitPercent)
	}
}

func TestParseArgsConfigAndOverrides(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sandbox.yaml")
	if err := os.WriteFile(path, []byte("command: [/bin/echo, from-config]\nnetwork_mode: host\nfile_size_limit_mb: 4\n"), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := ParseArgs([]string{"--verbose", "--config", path, "--file-size-limit", "8"})
	if err != nil {
		t.Fatal(err)
	}
	if !got.Verbose || string(got.Config.NetworkMode) != "host" || got.Config.FileSizeLimitMB != 8 {
		t.Fatalf("config/override lost: %+v", got)
	}
}

func TestParseArgsRejectsInvalidPublicSyntax(t *testing.T) {
	for _, argv := range [][]string{{}, {"--unknown", "/bin/echo"}, {"--verbose", "--verbose", "/bin/echo"}, {"--file-size-limit"}} {
		if _, err := ParseArgs(argv); err == nil {
			t.Errorf("ParseArgs(%q) accepted invalid input", argv)
		}
	}
}

func TestParseArgsStopsFlagsAtDoubleDash(t *testing.T) {
	got, err := ParseArgs([]string{"--network-mode", "none", "--", "/bin/echo", "--file-size-limit", ""})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Config.Command) != 3 || got.Config.Command[1] != "--file-size-limit" {
		t.Fatalf("command parsing changed: %#v", got.Config.Command)
	}
}
