//go:build linux

package child

import (
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestMain(m *testing.M) {
	if role := os.Getenv("SANDBOX_CHILD_TEST_INIT"); role != "" {
		_ = os.Unsetenv("SANDBOX_CHILD_TEST_INIT")
		environment := append(os.Environ(), "SANDBOX_CHILD_TEST_PAYLOAD="+role)
		os.Exit(runInit(os.Args[0], []string{os.Args[0]}, environment))
	}
	if role := os.Getenv("SANDBOX_CHILD_TEST_PAYLOAD"); role != "" {
		payloadTestMain(role)
		return
	}
	os.Exit(m.Run())
}

func payloadTestMain(role string) {
	if role == "process-group" {
		if err := syscall.Setpgid(0, 0); err != nil {
			os.Exit(125)
		}
	}
	if ready := os.Getenv("SANDBOX_CHILD_TEST_READY"); ready != "" {
		if err := os.WriteFile(ready, []byte("ready\n"), 0600); err != nil {
			os.Exit(125)
		}
	}
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGTERM)
	defer signal.Stop(signals)
	<-signals
	os.Exit(128 + int(syscall.SIGTERM))
}

func TestRunInitForwardsSignalsToNormalPayload(t *testing.T) {
	testRunInitSignal(t, "normal")
}

func TestRunInitForwardsSignalsAfterPayloadChangesProcessGroup(t *testing.T) {
	testRunInitSignal(t, "process-group")
}

func testRunInitSignal(t *testing.T, role string) {
	t.Helper()
	ready := filepath.Join(t.TempDir(), "ready")
	environment := append(os.Environ(),
		"SANDBOX_CHILD_TEST_INIT="+role,
		"SANDBOX_CHILD_TEST_READY="+ready,
	)
	command := exec.Command(os.Args[0], "-test.run=^$")
	command.Env = environment
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if command.Process != nil && command.ProcessState == nil {
			_ = command.Process.Kill()
			_ = command.Wait()
		}
	})
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(ready); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("payload did not report startup")
		}
		time.Sleep(time.Millisecond)
	}
	if err := command.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	err := command.Wait()
	if exitErr, ok := err.(*exec.ExitError); !ok || exitErr.ExitCode() != 128+int(syscall.SIGTERM) {
		if err == nil {
			t.Fatalf("init helper exited successfully, want %d", 128+int(syscall.SIGTERM))
		}
		t.Fatalf("init helper error = %v, want exit status %d", err, 128+int(syscall.SIGTERM))
	}
}
