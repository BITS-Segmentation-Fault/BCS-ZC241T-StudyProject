//go:build linux

package parent

import (
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"regexp"
	"strings"
	"sync"
	"syscall"

	"github.com/creack/pty"
	"golang.org/x/sys/unix"
	"golang.org/x/term"
)

const (
	defaultTerminalColumns = 80
	defaultTerminalRows    = 24
)

var terminalNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]{0,31}$`)

type interactiveTerminal struct {
	stdin  *os.File
	stdout *os.File
	stderr *os.File
	size   *pty.Winsize

	master     *os.File
	inputStop  chan struct{}
	inputDone  chan struct{}
	outputDone chan struct{}

	state *term.State

	resizeDone chan struct{}
	resizeWait sync.WaitGroup
}

func newInteractiveTerminal(stdin, stdout, stderr *os.File) (*interactiveTerminal, error) {
	if stdin == nil || !term.IsTerminal(int(stdin.Fd())) {
		return nil, errors.New("interactive mode requires stdin to be a terminal")
	}
	if stdout == nil || !term.IsTerminal(int(stdout.Fd())) {
		log.Printf("[TERMINAL] stdout is not a terminal; continuing with separate stderr")
	}
	return &interactiveTerminal{stdin: stdin, stdout: stdout, stderr: stderr}, nil
}

func (t *interactiveTerminal) start(cmd *exec.Cmd, attrs *syscall.SysProcAttr) error {
	size := currentTerminalSize(t.stdin)
	cmd.Stderr = t.stderr
	master, err := pty.StartWithAttrs(cmd, size, attrs)
	if err != nil {
		return err
	}
	t.master = master
	t.size = size
	t.inputStop = make(chan struct{})
	t.inputDone = make(chan struct{})
	t.outputDone = make(chan struct{})
	go t.copyInput()
	go t.copyOutput()
	return nil
}

func currentTerminalSize(stdin *os.File) *pty.Winsize {
	size, err := pty.GetsizeFull(stdin)
	if err == nil && size.Rows != 0 && size.Cols != 0 {
		return size
	}
	if err == nil {
		err = errors.New("terminal reported zero dimensions")
	}
	log.Printf("[TERMINAL] cannot determine terminal size: %v; using %dx%d", err, defaultTerminalColumns, defaultTerminalRows)
	return &pty.Winsize{Cols: defaultTerminalColumns, Rows: defaultTerminalRows}
}

func (t *interactiveTerminal) copyInput() {
	defer close(t.inputDone)
	buffer := make([]byte, 32*1024)
	for {
		select {
		case <-t.inputStop:
			return
		default:
		}
		pollFD := []unix.PollFd{{Fd: int32(t.stdin.Fd()), Events: unix.POLLIN}}
		if _, err := unix.Poll(pollFD, 100); err != nil {
			if errors.Is(err, unix.EINTR) {
				continue
			}
			return
		}
		if pollFD[0].Revents&(unix.POLLIN|unix.POLLHUP|unix.POLLERR) == 0 {
			continue
		}
		count, err := unix.Read(int(t.stdin.Fd()), buffer)
		if count > 0 {
			pending := buffer[:count]
			for len(pending) > 0 {
				written, writeErr := t.master.Write(pending)
				if writeErr != nil || written == 0 {
					return
				}
				pending = pending[written:]
			}
		}
		if err != nil || count == 0 {
			return
		}
	}
}

func (t *interactiveTerminal) copyOutput() {
	defer close(t.outputDone)
	err := copyTerminalOutput(t.stdout, t.master)
	if err != nil {
		log.Printf("[TERMINAL] output forwarding failed: %v", err)
	}
}

func copyTerminalOutput(dst io.Writer, src io.Reader) error {
	_, err := io.Copy(dst, src)
	if errors.Is(err, syscall.EIO) {
		return nil
	}
	return err
}

func (t *interactiveTerminal) makeRaw() error {
	fd := int(t.stdin.Fd())
	original, err := term.GetState(fd)
	if err != nil {
		return fmt.Errorf("read terminal state: %w", err)
	}
	originalTermios, err := unix.IoctlGetTermios(fd, unix.TCGETS)
	if err != nil {
		return fmt.Errorf("read terminal flags: %w", err)
	}
	if _, err := term.MakeRaw(fd); err != nil {
		return errors.Join(
			fmt.Errorf("set terminal raw mode: %w", err),
			restoreTerminalState(fd, original),
		)
	}
	rawTermios, err := unix.IoctlGetTermios(fd, unix.TCGETS)
	if err != nil {
		return errors.Join(
			fmt.Errorf("read raw terminal flags: %w", err),
			restoreTerminalState(fd, original),
		)
	}
	rawTermios.Oflag = originalTermios.Oflag
	if err := unix.IoctlSetTermios(fd, unix.TCSETS, rawTermios); err != nil {
		return errors.Join(
			fmt.Errorf("restore terminal output flags: %w", err),
			restoreTerminalState(fd, original),
		)
	}
	// Do not publish cleanup state until raw mode and output flags are both set.
	t.state = original
	return nil
}

func restoreTerminalState(fd int, state *term.State) error {
	if err := term.Restore(fd, state); err != nil {
		return fmt.Errorf("restore terminal state: %w", err)
	}
	return nil
}

func (t *interactiveTerminal) watchResize() func() {
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGWINCH)
	t.resizeDone = make(chan struct{})
	t.resizeWait.Add(1)
	go func() {
		defer t.resizeWait.Done()
		for {
			select {
			case <-t.resizeDone:
				return
			case <-signals:
				t.resize()
			}
		}
	}()
	return func() {
		signal.Stop(signals)
		close(t.resizeDone)
		t.resizeWait.Wait()
	}
}

func (t *interactiveTerminal) resize() {
	size, err := pty.GetsizeFull(t.stdin)
	if err == nil && size.Rows != 0 && size.Cols != 0 {
		if err = pty.Setsize(t.master, size); err == nil {
			t.size = size
			return
		}
	}
	if err == nil {
		err = errors.New("terminal reported zero dimensions")
	}
	log.Printf("[TERMINAL] resize failed: %v; retaining %dx%d", err, t.size.Cols, t.size.Rows)
}

func (t *interactiveTerminal) close() error {
	var result error
	if t.master != nil {
		close(t.inputStop)
		<-t.inputDone
		<-t.outputDone
		if err := t.master.Close(); err != nil && !errors.Is(err, os.ErrClosed) {
			result = errors.Join(result, err)
		}
	}
	if t.state != nil {
		if err := restoreTerminalState(int(t.stdin.Fd()), t.state); err != nil {
			result = errors.Join(result, err)
		}
	}
	return result
}

func interactiveEnvironment(environment []string, hostTERM string, configuredTERM string, configured bool) []string {
	value := configuredTERM
	if !configured {
		value = hostTERM
		if !terminalNamePattern.MatchString(value) {
			log.Printf("[TERMINAL] invalid or missing TERM; using TERM=dumb")
			value = "dumb"
		}
	}
	result := make([]string, 0, len(environment)+1)
	for _, entry := range environment {
		if key, _, ok := strings.Cut(entry, "="); ok && key == "TERM" {
			continue
		}
		result = append(result, entry)
	}
	return append(result, "TERM="+value)
}

func configuredEnvironmentValue(environment []string, name string) (string, bool) {
	for _, entry := range environment {
		key, value, ok := strings.Cut(entry, "=")
		if ok && key == name {
			return value, true
		}
	}
	return "", false
}
