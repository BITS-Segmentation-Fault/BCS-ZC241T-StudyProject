//go:build linux

package resources

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

const cgroupHelperEnvironment = "SANDBOX_CGROUP_RESOURCE_HELPER"

type unavailableCgroupPrerequisite struct {
	reason string
	err    error
}

func (e *unavailableCgroupPrerequisite) Error() string { return e.reason }
func (e *unavailableCgroupPrerequisite) Unwrap() error { return e.err }

func markUnavailableCgroupPrerequisite(reason string, err error) error {
	return &unavailableCgroupPrerequisite{reason: reason, err: err}
}

func isUnavailableCgroupPrerequisite(err error) bool {
	var unavailable *unavailableCgroupPrerequisite
	return errors.As(err, &unavailable)
}

func classifyCgroupAPIError(operation string, err error) error {
	if errors.Is(err, unix.ENOENT) || errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) || errors.Is(err, unix.EROFS) || errors.Is(err, unix.ENOSYS) || errors.Is(err, unix.EOPNOTSUPP) {
		return markUnavailableCgroupPrerequisite(fmt.Sprintf("%s: %v", operation, err), err)
	}
	return fmt.Errorf("%s: %w", operation, err)
}

func TestDelegatedResourceControls(t *testing.T) {
	if os.Getenv(cgroupHelperEnvironment) == "1" {
		for {
			time.Sleep(time.Hour)
		}
	}

	if err := delegatedResourcePrerequisite(); err != nil {
		if isUnavailableCgroupPrerequisite(err) {
			if os.Getenv("SANDBOX_CGROUP_E2E_REQUIRED") == "1" {
				t.Fatalf("required cgroup prerequisite unavailable: %v", err)
			}
			t.Skipf("cgroup prerequisite unavailable: %v", err)
		}
		t.Fatalf("cgroup prerequisite probe failed: %v", err)
	}

	limit, err := PrepareResourceLimits(1, 1, 64)
	if err != nil {
		t.Fatalf("PrepareResourceLimits() after prerequisite probe: %v", err)
	}
	if limit == nil {
		t.Fatal("PrepareResourceLimits() returned no resource cgroup")
	}
	path := limit.path
	defer func() {
		if err := limit.Cleanup(); err != nil {
			t.Errorf("resource cgroup cleanup failed: %v", err)
		}
	}()

	cmd := exec.Command(os.Args[0], "-test.run=^TestDelegatedResourceControls$", "-test.v")
	env := make([]string, 0, len(os.Environ())+1)
	for _, entry := range os.Environ() {
		if !strings.HasPrefix(entry, cgroupHelperEnvironment+"=") {
			env = append(env, entry)
		}
	}
	cmd.Env = append(env, cgroupHelperEnvironment+"=1")
	if err := cmd.Start(); err != nil {
		t.Fatalf("start blocked helper: %v", err)
	}
	helperReaped := false
	defer func() {
		if !helperReaped {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	}()
	if err := limit.Attach(cmd.Process.Pid); err != nil {
		t.Fatalf("attach helper to resource cgroup: %v", err)
	}

	for file, want := range map[string]string{
		"cpu.max":          "1000 100000\n",
		"memory.max":       "1073741824\n",
		"memory.swap.max":  "0\n",
		"memory.oom.group": "1\n",
		"pids.max":         "64\n",
	} {
		data, err := os.ReadFile(filepath.Join(path, file))
		if err != nil {
			t.Fatalf("read %s: %v", file, err)
		}
		if string(data) != want {
			t.Errorf("%s = %q, want %q", file, data, want)
		}
	}
	procs, err := os.ReadFile(filepath.Join(path, "cgroup.procs"))
	if err != nil {
		t.Fatalf("read cgroup.procs: %v", err)
	}
	if !containsLine(string(procs), strconv.Itoa(cmd.Process.Pid)) {
		t.Fatalf("attached helper PID %d absent from cgroup.procs: %q", cmd.Process.Pid, procs)
	}

	if err := cmd.Process.Kill(); err != nil {
		t.Fatalf("kill blocked helper: %v", err)
	}
	waitErr := cmd.Wait()
	helperReaped = true
	if waitErr == nil {
		t.Fatal("blocked helper unexpectedly exited successfully")
	}
	if err := limit.Cleanup(); err != nil {
		t.Fatalf("cleanup resource cgroup: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("resource cgroup stat after cleanup = %v, want not exists", err)
	}
}

func delegatedResourcePrerequisite() error {
	data, err := os.ReadFile(procSelfCgroup)
	if err != nil {
		return classifyCgroupAPIError("read process cgroup membership", err)
	}
	relative, err := parseUnifiedCgroupPath(strings.NewReader(string(data)))
	if err != nil {
		return err
	}
	delegated, err := resolveDelegatedCgroupPath(cgroupMount, relative)
	if err != nil {
		return err
	}
	var stat unix.Statfs_t
	if err := unix.Statfs(delegated, &stat); err != nil {
		return classifyCgroupAPIError("inspect delegated filesystem", err)
	}
	if stat.Type != unix.CGROUP2_SUPER_MAGIC {
		return markUnavailableCgroupPrerequisite("delegated path is not cgroup-v2", nil)
	}
	controllers, err := os.ReadFile(filepath.Join(delegated, "cgroup.controllers"))
	if err != nil {
		return classifyCgroupAPIError("read available controllers", err)
	}
	subtree, err := os.ReadFile(filepath.Join(delegated, "cgroup.subtree_control"))
	if err != nil {
		return classifyCgroupAPIError("read delegated controllers", err)
	}
	for _, controller := range []string{"cpu", "memory", "pids"} {
		if !containsWord(string(controllers), controller) || !containsWord(string(subtree), controller) {
			return markUnavailableCgroupPrerequisite(controller+" controller is not available and delegated", nil)
		}
	}

	probe, err := os.MkdirTemp(delegated, "sandbox-probe-")
	if err != nil {
		return classifyCgroupAPIError("create delegated probe cgroup", err)
	}
	probeRemoved := false
	removeProbe := func(cause error) error {
		if probeRemoved {
			return cause
		}
		if removeErr := os.Remove(probe); removeErr != nil {
			return fmt.Errorf("remove delegated probe cgroup after %v: %w", cause, removeErr)
		}
		probeRemoved = true
		return cause
	}
	for _, file := range []string{"cpu.max", "memory.max", "memory.swap.max", "memory.oom.group", "pids.max", "cgroup.procs"} {
		if _, err := os.Stat(filepath.Join(probe, file)); err != nil {
			classified := classifyCgroupAPIError("verify delegated control file "+file, err)
			return removeProbe(classified)
		}
	}
	if err := os.Remove(probe); err != nil {
		return fmt.Errorf("remove delegated probe cgroup: %w", err)
	}
	return nil
}

func containsLine(value, want string) bool {
	for _, line := range strings.Split(value, "\n") {
		if line == want {
			return true
		}
	}
	return false
}

func TestCgroupPrerequisiteErrorClassification(t *testing.T) {
	for _, errno := range []error{unix.EPERM, unix.EACCES, unix.EROFS, unix.ENOSYS, unix.EOPNOTSUPP} {
		if !isUnavailableCgroupPrerequisite(classifyCgroupAPIError("mount API", errno)) {
			t.Errorf("%v was not classified as unavailable", errno)
		}
	}
	if isUnavailableCgroupPrerequisite(classifyCgroupAPIError("fixture setup", unix.EINVAL)) {
		t.Error("ordinary fixture error was classified as unavailable")
	}
	if isUnavailableCgroupPrerequisite(fmt.Errorf("ordinary fixture error: %w", unix.EPERM)) {
		t.Error("ordinary wrapped EPERM was classified as unavailable")
	}
	if isUnavailableCgroupPrerequisite(classifyCgroupAPIError("mount API", unix.EINVAL)) {
		t.Error("EINVAL was classified as unavailable")
	}
}
