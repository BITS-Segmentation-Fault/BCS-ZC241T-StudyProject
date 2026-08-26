//go:build linux

package security

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"syscall"
	"testing"

	"sandbox/sandbox/config"

	"golang.org/x/sys/unix"
)

const seccompHelperMode = "SANDBOX_SECCOMP_HELPER"

func TestMain(m *testing.M) {
	if mode := os.Getenv(seccompHelperMode); mode != "" {
		os.Exit(runSeccompHelperMode(mode))
	}
	os.Exit(m.Run())
}

func runSeccompHelperMode(mode string) int {
	switch mode {
	case "kill":
		if !installSeccompForHelper(config.ActionKill) {
			return 100
		}
		invokeBlockedSyslog()
	case "trap":
		if !installSeccompForHelper(config.ActionTrap) {
			return 100
		}
		invokeBlockedSyslog()
	case "allowed":
		if !installSeccompForHelper(config.ActionKill) {
			return 100
		}
		pid, _, errno := unix.RawSyscall(unix.SYS_GETPID, 0, 0, 0)
		if errno != 0 {
			fmt.Fprintf(os.Stderr, "getpid failed: %v\n", errno)
			os.Exit(2)
		}
		fmt.Printf("allowed-ok pid=%d\n", pid)
		status, err := os.ReadFile("/proc/self/status")
		if err != nil {
			fmt.Fprintf(os.Stderr, "status read failed: %v\n", err)
			os.Exit(3)
		}
		for _, line := range strings.Split(string(status), "\n") {
			if strings.HasPrefix(line, "NoNewPrivs:") {
				normalized := strings.Join(strings.Fields(line), " ")
				fmt.Println(normalized)
				if normalized != "NoNewPrivs: 1" {
					os.Exit(4)
				}
				return 0
			}
		}
		fmt.Fprintln(os.Stderr, "NoNewPrivs line was not found")
		os.Exit(5)
	case "tsync":
		return runTSYNCHelper()
	default:
		fmt.Fprintf(os.Stderr, "unknown seccomp helper mode %q\n", mode)
		return 102
	}
	return 0
}

func TestSeccompKernelKillAction(t *testing.T) {
	assertSeccompBlocked(t, "kill")
}

func TestSeccompKernelTrapAction(t *testing.T) {
	assertSeccompBlocked(t, "trap")
}

func TestSeccompKernelAllowsUnblockedSyscall(t *testing.T) {
	output, err := runSeccompHelper(t, "allowed")
	if err != nil {
		t.Fatalf("allowed syscall helper failed: %v\n%s", err, output)
	}
	if !strings.Contains(output, "allowed-ok") || !strings.Contains(output, "NoNewPrivs:") {
		t.Fatalf("allowed syscall helper output = %q", output)
	}
}

func TestSeccompKernelSynchronizesThreads(t *testing.T) {
	assertSeccompBlocked(t, "tsync")
}

func installSeccompForHelper(action config.SeccompAction) bool {
	if err := ApplySeccompFilter(action, []string{"syslog"}); err != nil {
		fmt.Fprintf(os.Stderr, "seccomp installation failed: %v\n", err)
		return false
	}
	return true
}

func invokeBlockedSyslog() {
	_, _, _ = unix.RawSyscall(unix.SYS_SYSLOG, 0, 0, 0)
	fmt.Fprintln(os.Stderr, "blocked syscall survived")
	os.Exit(101)
}

func runTSYNCHelper() int {
	runtime.LockOSThread()
	ready := make(chan int)
	proceed := make(chan struct{})
	go func() {
		runtime.LockOSThread()
		ready <- unix.Gettid()
		<-proceed
		invokeBlockedSyslog()
	}()
	workerTID := <-ready
	if workerTID == unix.Gettid() {
		fmt.Fprintf(os.Stderr, "TSYNC helper did not use a distinct thread: %d\n", workerTID)
		return 103
	}
	if !installSeccompForHelper(config.ActionKill) {
		return 100
	}
	close(proceed)
	select {}
}

func assertSeccompBlocked(t *testing.T, mode string) {
	t.Helper()
	output, err := runSeccompHelper(t, mode)
	if err == nil {
		t.Fatalf("%s action helper survived blocked syscall: %s", mode, output)
	}
	exitErr, ok := err.(*exec.ExitError)
	if !ok {
		t.Fatalf("%s action helper error = %T %v", mode, err, err)
	}
	status, ok := exitErr.ProcessState.Sys().(syscall.WaitStatus)
	if !ok {
		t.Fatalf("%s action returned an unexpected process status, output = %s", mode, output)
	}
	if mode == "trap" {
		// The Go runtime converts a synchronous SIGSYS into its fatal
		// diagnostic and exits with status 2 instead of exposing the signal.
		if status.Exited() && status.ExitStatus() == 2 &&
			strings.Contains(output, "SIGSYS: bad system call") {
			return
		}
	} else if status.Signaled() && status.Signal() == syscall.SIGSYS {
		return
	}
	t.Fatalf("%s action status = %v, output = %s", mode, status, output)
}

func runSeccompHelper(t *testing.T, mode string) (string, error) {
	t.Helper()
	command := exec.Command(os.Args[0])
	command.Env = appendWithoutKey(os.Environ(), seccompHelperMode, mode)
	output, err := command.CombinedOutput()
	return string(output), err
}

func appendWithoutKey(environment []string, key, value string) []string {
	prefix := key + "="
	result := make([]string, 0, len(environment)+1)
	for _, entry := range environment {
		if !strings.HasPrefix(entry, prefix) {
			result = append(result, entry)
		}
	}
	return append(result, prefix+value)
}
