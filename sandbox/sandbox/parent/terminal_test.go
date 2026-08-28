//go:build linux

package parent

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"reflect"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/creack/pty"
	"golang.org/x/sys/unix"
	"golang.org/x/term"
)

func TestTerminalHelper(t *testing.T) {
	if os.Getenv("SANDBOX_TERMINAL_HELPER") != "1" {
		return
	}
	role := os.Getenv("SANDBOX_TERMINAL_ROLE")
	switch role {
	case "stdio":
		if !term.IsTerminal(int(os.Stdin.Fd())) || !term.IsTerminal(int(os.Stdout.Fd())) {
			fmt.Fprintln(os.Stderr, "stdio input/output descriptor is not a terminal")
			os.Exit(20)
		}
		fmt.Fprintln(os.Stdout, "READY 1 1 0")
		line, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil {
			os.Exit(21)
		}
		fmt.Fprintf(os.Stdout, "OUT %s", line)
		fmt.Fprintf(os.Stderr, "ERR %s", line)
	case "size":
		printTerminalSize()
	case "resize":
		signals := make(chan os.Signal, 1)
		signal.Notify(signals, syscall.SIGWINCH)
		printTerminalSize()
		<-signals
		printTerminalSize()
	case "ctrlc":
		signals := make(chan os.Signal, 1)
		signal.Notify(signals, syscall.SIGINT)
		fmt.Fprintln(os.Stdout, "READY")
		<-signals
		fmt.Fprintln(os.Stdout, "GOT INT")
	case "exit-error":
		fmt.Fprintln(os.Stdout, "READY")
		os.Exit(7)
	default:
		fmt.Fprintf(os.Stderr, "unknown helper role %q", role)
		os.Exit(22)
	}
}

func printTerminalSize() {
	size, err := unix.IoctlGetWinsize(0, unix.TIOCGWINSZ)
	if err != nil {
		fmt.Fprintf(os.Stderr, "size: %v", err)
		os.Exit(23)
	}
	fmt.Fprintf(os.Stdout, "SIZE %d %d\n", size.Row, size.Col)
}

type nestedTerminalSession struct {
	terminal *interactiveTerminal
	command  *exec.Cmd
	hostPTY  *os.File
	hostTTY  *os.File
	output   *os.File
	stderr   *os.File

	originalState *unix.Termios

	stopResize  func()
	cleanupOnce sync.Once
	cleanupErr  error
}

func startNestedTerminal(t *testing.T, role string, rows, cols uint16, beforeStart ...func(*os.File) error) *nestedTerminalSession {
	t.Helper()
	hostPTY, hostTTY, err := pty.Open()
	if err != nil {
		t.Fatal(err)
	}
	if err := pty.Setsize(hostPTY, &pty.Winsize{Rows: rows, Cols: cols}); err != nil {
		hostPTY.Close()
		hostTTY.Close()
		t.Fatal(err)
	}
	output, err := os.CreateTemp(t.TempDir(), "terminal-output-")
	if err != nil {
		hostPTY.Close()
		hostTTY.Close()
		t.Fatal(err)
	}
	stderr, err := os.CreateTemp(t.TempDir(), "terminal-stderr-")
	if err != nil {
		output.Close()
		hostPTY.Close()
		hostTTY.Close()
		t.Fatal(err)
	}
	terminal, err := newInteractiveTerminal(hostTTY, output, stderr)
	if err != nil {
		output.Close()
		stderr.Close()
		hostPTY.Close()
		hostTTY.Close()
		t.Fatal(err)
	}
	if len(beforeStart) > 0 {
		if err := beforeStart[0](hostPTY); err != nil {
			output.Close()
			stderr.Close()
			hostPTY.Close()
			hostTTY.Close()
			t.Fatal(err)
		}
	}
	command := exec.Command(os.Args[0], "-test.run=^TestTerminalHelper$")
	command.Env = append(os.Environ(), "SANDBOX_TERMINAL_HELPER=1", "SANDBOX_TERMINAL_ROLE="+role)
	if err := terminal.start(command, &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}); err != nil {
		output.Close()
		stderr.Close()
		hostPTY.Close()
		hostTTY.Close()
		t.Fatal(err)
	}
	session := &nestedTerminalSession{terminal: terminal, command: command, hostPTY: hostPTY, hostTTY: hostTTY, output: output, stderr: stderr}
	t.Cleanup(func() { session.cleanup(t) })
	session.originalState, err = unix.IoctlGetTermios(int(hostTTY.Fd()), unix.TCGETS)
	if err != nil {
		t.Fatal(err)
	}
	if err := terminal.makeRaw(); err != nil {
		t.Fatal(err)
	}
	return session
}

func (s *nestedTerminalSession) stopResizeWatcher() {
	if stop := s.stopResize; stop != nil {
		s.stopResize = nil
		stop()
	}
}

func (s *nestedTerminalSession) closeResources() error {
	s.cleanupOnce.Do(func() {
		if err := s.terminal.close(); err != nil {
			s.cleanupErr = errors.Join(s.cleanupErr, err)
		}
		if s.originalState != nil {
			after, err := unix.IoctlGetTermios(int(s.hostTTY.Fd()), unix.TCGETS)
			if err != nil {
				s.cleanupErr = errors.Join(s.cleanupErr, fmt.Errorf("read restored terminal state: %w", err))
			} else if !reflect.DeepEqual(s.originalState, after) {
				s.cleanupErr = errors.Join(s.cleanupErr, fmt.Errorf("terminal state changed: before=%+v after=%+v", s.originalState, after))
			}
		}
		if err := s.output.Close(); err != nil {
			s.cleanupErr = errors.Join(s.cleanupErr, fmt.Errorf("close terminal output: %w", err))
		}
		if err := s.stderr.Close(); err != nil {
			s.cleanupErr = errors.Join(s.cleanupErr, fmt.Errorf("close terminal stderr: %w", err))
		}
		if err := s.hostPTY.Close(); err != nil {
			s.cleanupErr = errors.Join(s.cleanupErr, fmt.Errorf("close host PTY: %w", err))
		}
		if err := s.hostTTY.Close(); err != nil {
			s.cleanupErr = errors.Join(s.cleanupErr, fmt.Errorf("close host TTY: %w", err))
		}
	})
	return s.cleanupErr
}

func (s *nestedTerminalSession) cleanup(t *testing.T) {
	var cleanupErr error
	if s.command.Process != nil && s.command.ProcessState == nil {
		if err := s.command.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
			cleanupErr = errors.Join(cleanupErr, fmt.Errorf("kill helper: %w", err))
		}
	}
	if s.command.Process != nil && s.command.ProcessState == nil {
		if err := s.command.Wait(); err != nil {
			var exitErr *exec.ExitError
			if !errors.As(err, &exitErr) {
				cleanupErr = errors.Join(cleanupErr, fmt.Errorf("reap helper: %w", err))
			}
		}
	}
	s.stopResizeWatcher()
	cleanupErr = errors.Join(cleanupErr, s.closeResources())
	if cleanupErr != nil {
		t.Errorf("terminal cleanup failed: %v", cleanupErr)
	}
}

func (s *nestedTerminalSession) finish(t *testing.T) (string, int) {
	t.Helper()
	s.stopResizeWatcher()
	err := s.command.Wait()
	if cleanupErr := s.closeResources(); cleanupErr != nil {
		t.Fatalf("terminal cleanup failed: %v", cleanupErr)
	}
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return readOutput(t, s.output.Name()), exitErr.ExitCode()
		}
		t.Fatal(err)
	}
	return readOutput(t, s.output.Name()), 0
}

func readOutput(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func waitForOutput(t *testing.T, path, want string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		data, err := os.ReadFile(path)
		if err == nil && strings.Contains(string(data), want) {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("output %q did not contain %q", path, want)
}

func TestInteractiveTerminalForwardsInputAndPreservesOutputStreams(t *testing.T) {
	session := startNestedTerminal(t, "stdio", 24, 80)
	waitForOutput(t, session.output.Name(), "READY 1 1 0")
	if _, err := session.hostPTY.Write([]byte("hello\n")); err != nil {
		t.Fatal(err)
	}
	waitForOutput(t, session.output.Name(), "OUT hello")
	output, status := session.finish(t)
	stderr := readOutput(t, session.stderr.Name())
	if status != 0 {
		t.Fatalf("helper status = %d, want 0; stdout=%q stderr=%q", status, output, stderr)
	}
	if !strings.Contains(output, "OUT hello") || strings.Contains(output, "ERR hello") {
		t.Fatalf("stdout = %q, want only stdout marker", output)
	}
	if !strings.Contains(stderr, "ERR hello") || strings.Contains(stderr, "OUT hello") {
		t.Fatalf("stderr = %q, want only stderr marker", stderr)
	}
}

func TestInteractiveTerminalRawModePreservesOutputAndRestoresState(t *testing.T) {
	session := startNestedTerminal(t, "size", 24, 80)
	raw, err := unix.IoctlGetTermios(int(session.hostTTY.Fd()), unix.TCGETS)
	if err != nil {
		t.Fatal(err)
	}
	if raw.Iflag&(unix.IGNBRK|unix.BRKINT|unix.PARMRK|unix.ISTRIP|unix.INLCR|unix.IGNCR|unix.ICRNL|unix.IXON) != 0 {
		t.Fatalf("raw input flags = %#x, expected input processing disabled", raw.Iflag)
	}
	if raw.Lflag&(unix.ECHO|unix.ECHONL|unix.ICANON|unix.ISIG|unix.IEXTEN) != 0 {
		t.Fatalf("raw local flags = %#x, expected canonical input, echo, and signals disabled", raw.Lflag)
	}
	if raw.Oflag != session.originalState.Oflag {
		t.Fatalf("raw output flags = %#x, want original %#x", raw.Oflag, session.originalState.Oflag)
	}
	_, status := session.finish(t)
	if status != 0 {
		t.Fatalf("size helper status = %d, want 0", status)
	}
}

func TestInteractiveTerminalUsesCurrentSizeAtStart(t *testing.T) {
	session := startNestedTerminal(t, "size", 24, 80, func(hostPTY *os.File) error {
		return pty.Setsize(hostPTY, &pty.Winsize{Rows: 40, Cols: 120})
	})
	waitForOutput(t, session.output.Name(), "SIZE 40 120")
	output, status := session.finish(t)
	if status != 0 || !strings.Contains(output, "SIZE 40 120") {
		t.Fatalf("size helper status/output = %d/%q", status, output)
	}
}

func TestInteractiveTerminalPropagatesResize(t *testing.T) {
	session := startNestedTerminal(t, "resize", 24, 80)
	session.stopResize = session.terminal.watchResize()
	waitForOutput(t, session.output.Name(), "SIZE 24 80")
	if err := pty.Setsize(session.hostPTY, &pty.Winsize{Rows: 40, Cols: 120}); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Kill(os.Getpid(), syscall.SIGWINCH); err != nil {
		t.Fatal(err)
	}
	waitForOutput(t, session.output.Name(), "SIZE 40 120")
	session.stopResizeWatcher()
	output, status := session.finish(t)
	if status != 0 || !strings.Contains(output, "SIZE 40 120") {
		t.Fatalf("resize helper status/output = %d/%q", status, output)
	}
}

func TestInteractiveTerminalCtrlCReachesForegroundApplication(t *testing.T) {
	session := startNestedTerminal(t, "ctrlc", 24, 80)
	waitForOutput(t, session.output.Name(), "READY")
	if _, err := session.hostPTY.Write([]byte{3}); err != nil {
		t.Fatal(err)
	}
	waitForOutput(t, session.output.Name(), "GOT INT")
	output, status := session.finish(t)
	if status != 0 || !strings.Contains(output, "GOT INT") {
		t.Fatalf("ctrl-c helper status/output = %d/%q", status, output)
	}
}

func TestInteractiveTerminalReportsHelperExitStatus(t *testing.T) {
	session := startNestedTerminal(t, "exit-error", 24, 80)
	waitForOutput(t, session.output.Name(), "READY")
	output, status := session.finish(t)
	if status != 7 {
		t.Fatalf("helper status = %d, want 7; output=%q", status, output)
	}
}

func TestCopyTerminalOutputTreatsPTYEIOAsEOF(t *testing.T) {
	var output bytes.Buffer
	if err := copyTerminalOutput(&output, eioReader{}); err != nil {
		t.Fatalf("copyTerminalOutput() = %v, want nil", err)
	}
}

func TestInteractiveTerminalReportsRawSetupAndRestoreErrors(t *testing.T) {
	hostPTY, hostTTY, err := pty.Open()
	if err != nil {
		t.Fatal(err)
	}
	terminal, err := newInteractiveTerminal(hostTTY, os.Stdout, os.Stderr)
	if err != nil {
		hostTTY.Close()
		hostPTY.Close()
		t.Fatal(err)
	}
	if err := hostTTY.Close(); err != nil {
		hostPTY.Close()
		t.Fatal(err)
	}
	if err := terminal.makeRaw(); err == nil || !strings.Contains(err.Error(), "terminal state") {
		t.Fatalf("makeRaw() error = %v, want setup error", err)
	}
	if terminal.state != nil {
		t.Fatal("failed raw-mode setup retained cleanup state")
	}
	if err := hostPTY.Close(); err != nil {
		t.Fatal(err)
	}

	master, slave, err := pty.Open()
	if err != nil {
		t.Fatal(err)
	}
	defer master.Close()
	restoring, err := newInteractiveTerminal(slave, os.Stdout, os.Stderr)
	if err != nil {
		slave.Close()
		t.Fatal(err)
	}
	if err := restoring.makeRaw(); err != nil {
		slave.Close()
		t.Fatal(err)
	}
	if err := slave.Close(); err != nil {
		t.Fatal(err)
	}
	if err := restoring.close(); err == nil || !strings.Contains(err.Error(), "restore terminal state") {
		t.Fatalf("close() error = %v, want restoration error", err)
	}
}

type eioReader struct{}

func (eioReader) Read([]byte) (int, error) { return 0, syscall.EIO }

func TestInteractiveTerminalRequiresStdinTerminal(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	defer writer.Close()
	if _, err := newInteractiveTerminal(reader, os.Stdout, os.Stderr); err == nil || !strings.Contains(err.Error(), "stdin to be a terminal") {
		t.Fatalf("newInteractiveTerminal() error = %v", err)
	}
}

func TestInteractiveTerminalRedirectedStdoutWarningAndSizeFallback(t *testing.T) {
	var logs bytes.Buffer
	previous := log.Writer()
	defer log.SetOutput(previous)
	log.SetOutput(&logs)
	session := startNestedTerminal(t, "size", 0, 0)
	log.SetOutput(previous)
	waitForOutput(t, session.output.Name(), "SIZE 24 80")
	result, status := session.finish(t)
	if status != 0 || !strings.Contains(result, "SIZE 24 80") {
		t.Fatalf("fallback helper status/output = %d/%q", status, result)
	}
	if session.terminal.size.Rows != defaultTerminalRows || session.terminal.size.Cols != defaultTerminalColumns {
		t.Fatalf("fallback terminal size = %+v, want %dx%d", session.terminal.size, defaultTerminalColumns, defaultTerminalRows)
	}
	if !strings.Contains(logs.String(), "stdout is not a terminal") || !strings.Contains(logs.String(), "using 80x24") {
		t.Fatalf("terminal warnings = %q", logs.String())
	}
}

func TestInteractiveTERMPolicy(t *testing.T) {
	configured := interactiveEnvironment([]string{"PATH=/bin", "TERM=screen"}, "xterm-256color", "screen", true)
	if !containsEnvironment(configured, "TERM=screen") {
		t.Fatalf("configured TERM missing: %#v", configured)
	}
	forwarded := interactiveEnvironment([]string{"PATH=/bin"}, "xterm-256color", "", false)
	if !containsEnvironment(forwarded, "TERM=xterm-256color") {
		t.Fatalf("forwarded TERM missing: %#v", forwarded)
	}
	for _, hostTERM := range []string{"", "bad term", strings.Repeat("x", 33)} {
		got := interactiveEnvironment([]string{"PATH=/bin"}, hostTERM, "", false)
		if !containsEnvironment(got, "TERM=dumb") {
			t.Fatalf("invalid TERM %q produced %#v", hostTERM, got)
		}
	}
}

func containsEnvironment(environment []string, want string) bool {
	for _, entry := range environment {
		if entry == want {
			return true
		}
	}
	return false
}
