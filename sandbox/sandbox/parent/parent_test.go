//go:build linux

package parent

import (
	"os/exec"
	"reflect"
	"testing"

	"sandbox/sandbox/config"
)

func TestWaitForChild_ReturnsChildExitCode(t *testing.T) {
	cmd := exec.Command("/bin/sh", "-c", "exit 7")
	if err := cmd.Start(); err != nil {
		t.Fatalf("start child: %v", err)
	}

	if got := waitForChild(cmd, nil, config.DefaultConfig()); got != 7 {
		t.Fatalf("waitForChild() = %d, want 7", got)
	}
}

func TestWaitForChild_ReturnsSuccess(t *testing.T) {
	cmd := exec.Command("/bin/sh", "-c", "exit 0")
	if err := cmd.Start(); err != nil {
		t.Fatalf("start child: %v", err)
	}

	if got := waitForChild(cmd, nil, config.DefaultConfig()); got != 0 {
		t.Fatalf("waitForChild() = %d, want 0", got)
	}
}

func TestWaitForChild_ReturnsSignalStatus(t *testing.T) {
	cmd := exec.Command("/bin/sh", "-c", "kill -TERM $$")
	if err := cmd.Start(); err != nil {
		t.Fatalf("start child: %v", err)
	}
	if got := waitForChild(cmd, nil, config.DefaultConfig()); got != 143 {
		t.Fatalf("waitForChild() = %d, want 143", got)
	}
}

func TestSnapshotEnvironment(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.EnvVars = []string{"PATH=/custom", "PROBE_VALUE=explicit"}
	cfg.EnvWhitelist = []string{"PROBE_VALUE", "ALLOWED"}
	snapshot := snapshotEnvironment(cfg, []string{
		"PATH=/host",
		"PROBE_VALUE=host",
		"ALLOWED=host-value",
		"SECRET=should-not-cross",
	})
	if got, want := snapshot.EnvVars, []string{"PATH=/custom", "PROBE_VALUE=explicit", "ALLOWED=host-value"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("snapshot EnvVars = %#v, want %#v", got, want)
	}
	if snapshot.EnvWhitelist != nil {
		t.Fatalf("snapshot EnvWhitelist = %#v, want nil", snapshot.EnvWhitelist)
	}
	snapshot.EnvVars[0] = "PATH=/changed"
	if cfg.EnvVars[0] != "PATH=/custom" {
		t.Fatalf("snapshot shares EnvVars storage with input")
	}
	if got, want := internalChildEnvironment(snapshot.EnvVars), []string{"PATH=/changed"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("internal child environment = %#v, want %#v", got, want)
	}
	if got := internalChildEnvironment([]string{"PROBE_VALUE=host", "SECRET=should-not-cross"}); got == nil || len(got) != 0 {
		t.Fatalf("internal child environment without PATH = %#v, want non-nil empty slice", got)
	}
}
