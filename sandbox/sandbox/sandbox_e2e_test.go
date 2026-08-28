package main

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestSandboxRootlessHostAndNone(t *testing.T) {
	namespacesAvailable(t)
	sandbox := sandboxTestBinary(t)
	probe := probeTestBinary(t)
	parentUserNS := namespaceLink(t, "/proc/self/ns/user")
	parentPIDNS := namespaceLink(t, "/proc/self/ns/pid")
	parentNetNS := namespaceLink(t, "/proc/self/ns/net")
	for _, mode := range []string{"host", "none"} {
		t.Run(mode, func(t *testing.T) {
			rootfs := makeProbeRootfs(t, probe)
			sentinel := filepath.Join(t.TempDir(), "host-only-sentinel")
			if err := os.WriteFile(sentinel, []byte("host-secret"), 0600); err != nil {
				t.Fatal(err)
			}
			cfg := newSandboxConfig(rootfs, mode, "/bin/probe", "inspect")
			output, err := exec.Command(sandbox, "--config", writeSandboxConfig(t, cfg)).CombinedOutput()
			if err != nil {
				t.Fatalf("sandbox %s execution failed: %v\n%s", mode, err, output)
			}
			text := string(output)
			if got, want := findLine(text, "uid_map="), fmt.Sprintf("uid_map=0 %d 1", os.Getuid()); got != want {
				t.Fatalf("uid map = %q, want %q\n%s", got, want, text)
			}
			if got, want := findLine(text, "gid_map="), fmt.Sprintf("gid_map=0 %d 1", os.Getgid()); got != want {
				t.Fatalf("gid map = %q, want %q\n%s", got, want, text)
			}
			if got := findLine(text, "setgroups="); got != "setgroups=deny" {
				t.Fatalf("setgroups = %q, want deny\n%s", got, text)
			}
			requireSupervisedPayloadIdentity(t, text, "/work")
			if got := findLine(text, "userns="); got == "" || got == parentUserNS {
				t.Fatalf("user namespace was not isolated: %q", got)
			}
			if got := findLine(text, "pidns="); got == "" || got == parentPIDNS {
				t.Fatalf("PID namespace was not isolated: %q", got)
			}
			if got := findLine(text, "netns="); got == "" {
				t.Fatal("probe did not report network namespace")
			} else if mode == "host" && got != "netns="+parentNetNS {
				t.Fatalf("host mode changed network namespace: %q, want %s", got, parentNetNS)
			} else if mode == "none" && got == "netns="+parentNetNS {
				t.Fatalf("none mode retained network namespace: %q", got)
			}
			if mode == "none" {
				for prefix, want := range map[string]string{
					"interfaces=":    "interfaces=lo",
					"loopback=":      "loopback=up",
					"default-route=": "default-route=none",
					"ipv6=":          "ipv6=none",
				} {
					if got := findLine(text, prefix); got != want {
						t.Fatalf("none mode %s = %q, want %q\n%s", prefix, got, want, text)
					}
				}
			}
			visibility := newSandboxConfig(rootfs, mode, "/bin/probe", "read", sentinel)
			visibilityOutput, visibilityErr := exec.Command(sandbox, "--config", writeSandboxConfig(t, visibility)).CombinedOutput()
			if visibilityErr != nil || !strings.HasPrefix(findLine(string(visibilityOutput), "read-error="), "read-error=") || strings.Contains(string(visibilityOutput), "host-secret") {
				t.Fatalf("sandbox %s exposed host sentinel: %v\n%s", mode, visibilityErr, visibilityOutput)
			}
		})
	}
}

func TestSandboxInternalEnvironmentDoesNotLeakHostValues(t *testing.T) {
	namespacesAvailable(t)
	rootfs := makeProbeRootfs(t, probeTestBinary(t))
	cfg := newSandboxConfig(rootfs, "host", "/bin/probe", "environment", "PROBE_VALUE")
	cfg.EnvVars = nil
	cfg.EnvWhitelist = []string{"PROBE_VALUE"}
	sandbox := sandboxTestBinary(t)
	command := exec.Command(sandbox, "--config", writeSandboxConfig(t, cfg))
	command.Env = withEnvironment(os.Environ(), "PROBE_VALUE", "allowed-value")
	command.Env = withEnvironment(command.Env, "SANDBOX_PARENT_SECRET", "must-not-leak")
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("environment isolation failed: %v\n%s", err, output)
	}
	text := string(output)
	if findLine(text, "environment=PROBE_VALUE=") != "environment=PROBE_VALUE=allowed-value" {
		t.Fatalf("payload did not receive whitelisted value: %s", text)
	}
	procConfig := newSandboxConfig(rootfs, "host", "/bin/probe", "read", "/proc/1/environ")
	procConfig.EnvVars = nil
	procConfig.EnvWhitelist = []string{"PROBE_VALUE"}
	procCommand := exec.Command(sandbox, "--config", writeSandboxConfig(t, procConfig))
	procCommand.Env = withEnvironment(os.Environ(), "PROBE_VALUE", "allowed-value")
	procCommand.Env = withEnvironment(procCommand.Env, "SANDBOX_PARENT_SECRET", "must-not-leak")
	procOutput, procErr := procCommand.CombinedOutput()
	if procErr != nil || findLine(string(procOutput), "read=") != "read=" {
		t.Fatalf("PID 1 environment was not exactly empty: err=%v output=%s", procErr, procOutput)
	}
}

func TestSandboxPreservesExitAndSignalStatus(t *testing.T) {
	namespacesAvailable(t)
	sandbox := sandboxTestBinary(t)
	rootfs := makeProbeRootfs(t, probeTestBinary(t))
	exitConfig := newSandboxConfig(rootfs, "host", "/bin/probe", "exit", "7")
	command := exec.Command(sandbox, "--config", writeSandboxConfig(t, exitConfig))
	output, err := command.CombinedOutput()
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != 7 {
		t.Fatalf("sandbox did not preserve exit code: err=%v output=%s", err, output)
	}

	signalConfig := newSandboxConfig(rootfs, "host", "/bin/probe", "sleep", "30s")
	running := exec.Command(sandbox, "--config", writeSandboxConfig(t, signalConfig))
	stdout, err := running.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	running.Stderr = &stderr
	if err := running.Start(); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(stdout)
	var outputLines []string
	for {
		line, readErr := reader.ReadString('\n')
		if line != "" {
			outputLines = append(outputLines, strings.TrimSuffix(line, "\n"))
			if line == "ready\n" {
				break
			}
		}
		if readErr != nil {
			_ = running.Process.Kill()
			_ = running.Wait()
			t.Fatalf("sandbox did not reach payload readiness: %v\nstdout=%s\nstderr=%s", readErr, strings.Join(outputLines, "\n"), stderr.String())
		}
	}
	if err := running.Process.Signal(syscall.SIGINT); err != nil {
		t.Fatal(err)
	}
	err = running.Wait()
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != 128+int(syscall.SIGINT) {
		t.Fatalf("sandbox did not preserve SIGINT status: err=%v\nstdout=%s\nstderr=%s", err, strings.Join(outputLines, "\n"), stderr.String())
	}
}
