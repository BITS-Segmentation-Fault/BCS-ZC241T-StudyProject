//go:build linux

package resources

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const (
	cgroupRoot      = "/sys/fs/cgroup"
	cgroupCPUPeriod = 100000
)

// ApplyCPULimit places pid in a private cgroup-v2 CPU quota. A nil cleanup
// function means that the requested limit is unrestricted.
func ApplyCPULimit(pid, percent int) (func(), error) {
	if percent == 0 {
		return nil, nil
	}
	if percent < 0 || percent > 100 {
		return nil, fmt.Errorf("cpu limit percent must be between 0 and 100")
	}

	controllers, err := os.ReadFile(filepath.Join(cgroupRoot, "cgroup.controllers"))
	if err != nil {
		return nil, fmt.Errorf("cannot read cgroup controllers: %v", err)
	}
	if !containsWord(string(controllers), "cpu") {
		return nil, fmt.Errorf("cgroup v2 CPU controller is unavailable")
	}
	subtree, err := os.ReadFile(filepath.Join(cgroupRoot, "cgroup.subtree_control"))
	if err != nil || !containsWord(string(subtree), "cpu") {
		return nil, fmt.Errorf("cgroup-v2 CPU controller is not delegated to the sandbox")
	}

	path, err := os.MkdirTemp(cgroupRoot, "sandbox-")
	if err != nil {
		return nil, fmt.Errorf("cannot create a delegated CPU cgroup: %v", err)
	}
	cleanup := func() { _ = os.Remove(path) }

	if err := configureCPULimit(path, pid, percent); err != nil {
		cleanup()
		return nil, err
	}
	return cleanup, nil
}

// CheckCPUSupport performs the privilege and filesystem checks before the
// launcher creates an isolated child. The actual cgroup attachment needs the
// child's PID and is therefore done after the readiness handshake.
func CheckCPUSupport(percent int) error {
	if percent < 0 || percent > 100 {
		return fmt.Errorf("cpu limit percent must be between 0 and 100")
	}
	if percent == 0 {
		return nil
	}
	controllers, err := os.ReadFile(filepath.Join(cgroupRoot, "cgroup.controllers"))
	if err != nil {
		return fmt.Errorf("cgroup-v2 is unavailable: %v", err)
	}
	if !containsWord(string(controllers), "cpu") {
		return fmt.Errorf("cgroup-v2 CPU controller is unavailable")
	}
	subtree, err := os.ReadFile(filepath.Join(cgroupRoot, "cgroup.subtree_control"))
	if err != nil || !containsWord(string(subtree), "cpu") {
		return fmt.Errorf("cgroup-v2 CPU controller is not delegated to the sandbox")
	}
	probe, err := os.MkdirTemp(cgroupRoot, "sandbox-preflight-")
	if err != nil {
		return fmt.Errorf("cgroup-v2 CPU delegation is unavailable: %v", err)
	}
	if err := os.Remove(probe); err != nil {
		return fmt.Errorf("cgroup-v2 CPU delegation cleanup failed: %v", err)
	}
	return nil
}

func configureCPULimit(path string, pid, percent int) error {
	quota := cgroupCPUPeriod * percent / 100
	if quota <= 0 {
		return fmt.Errorf("cpu limit percent must be greater than zero")
	}
	if err := os.WriteFile(filepath.Join(path, "cpu.max"), []byte(fmt.Sprintf("%d %d\n", quota, cgroupCPUPeriod)), 0600); err != nil {
		return fmt.Errorf("cannot configure CPU quota: %v", err)
	}
	if err := os.WriteFile(filepath.Join(path, "cgroup.procs"), []byte(strconv.Itoa(pid)+"\n"), 0600); err != nil {
		return fmt.Errorf("cannot attach child to CPU cgroup: %v", err)
	}
	return nil
}

func containsWord(value, want string) bool {
	for _, word := range strings.Fields(value) {
		if word == want {
			return true
		}
	}
	return false
}
