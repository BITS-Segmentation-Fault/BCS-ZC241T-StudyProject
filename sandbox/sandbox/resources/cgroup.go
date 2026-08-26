//go:build linux

package resources

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
)

const (
	procSelfCgroup  = "/proc/self/cgroup"
	cgroupMount     = "/sys/fs/cgroup"
	cgroupCPUPeriod = 100000
	gbToBytes       = 1024 * 1024 * 1024
)

// cgroupFileSystem contains the filesystem operations needed to provision a
// cgroup. Keeping them behind an interface makes the lifecycle testable
// without requiring a delegated cgroup hierarchy on the test host.
type cgroupFileSystem interface {
	ReadFile(string) ([]byte, error)
	MkdirTemp(string, string) (string, error)
	WriteFile(string, []byte) error
	Remove(string) error
}

type osCgroupFileSystem struct{}

func (osCgroupFileSystem) ReadFile(path string) ([]byte, error) {
	return os.ReadFile(path)
}

func (osCgroupFileSystem) MkdirTemp(dir, pattern string) (string, error) {
	return os.MkdirTemp(dir, pattern)
}

func (osCgroupFileSystem) WriteFile(path string, data []byte) error {
	return os.WriteFile(path, data, 0600)
}

func (osCgroupFileSystem) Remove(path string) error {
	return os.Remove(path)
}

// ResourceLimits owns a prepared cgroup-v2 hierarchy for the sandbox's
// requested CPU, memory, and process limits. Cleanup is retryable and
// idempotent after the cgroup has been removed.
type ResourceLimits struct {
	path       string
	filesystem cgroupFileSystem
	mu         sync.Mutex
}

// PrepareResourceLimits creates one delegated cgroup for all aggregate
// resource limits requested by the configuration. Zero disables an
// individual limit without touching the cgroup filesystem.
func PrepareResourceLimits(cpuPercent, memoryGB, maxProcesses int) (*ResourceLimits, error) {
	return prepareResourceLimits(cpuPercent, memoryGB, maxProcesses, procSelfCgroup, cgroupMount, osCgroupFileSystem{})
}

func prepareResourceLimits(cpuPercent, memoryGB, maxProcesses int, procPath, mountPath string, filesystem cgroupFileSystem) (*ResourceLimits, error) {
	if cpuPercent < 0 || cpuPercent > 100 {
		return nil, fmt.Errorf("cpu limit percent must be between 0 and 100")
	}
	if memoryGB < 0 {
		return nil, fmt.Errorf("memory limit must not be negative")
	}
	if maxProcesses < 0 {
		return nil, fmt.Errorf("process limit must not be negative")
	}
	if cpuPercent == 0 && memoryGB == 0 && maxProcesses == 0 {
		return nil, nil
	}

	procData, err := filesystem.ReadFile(procPath)
	if err != nil {
		return nil, fmt.Errorf("cannot read process cgroup membership: %v", err)
	}
	relativePath, err := parseUnifiedCgroupPath(strings.NewReader(string(procData)))
	if err != nil {
		return nil, err
	}
	delegatedPath, err := resolveDelegatedCgroupPath(mountPath, relativePath)
	if err != nil {
		return nil, err
	}

	controllers, err := filesystem.ReadFile(filepath.Join(delegatedPath, "cgroup.controllers"))
	if err != nil {
		return nil, fmt.Errorf("cgroup-v2 controllers are unavailable: %v", err)
	}
	subtree, err := filesystem.ReadFile(filepath.Join(delegatedPath, "cgroup.subtree_control"))
	if err != nil {
		return nil, fmt.Errorf("cgroup-v2 controllers are not delegated: %v", err)
	}
	for _, controller := range requestedControllers(cpuPercent, memoryGB, maxProcesses) {
		if !containsWord(string(controllers), controller) {
			return nil, fmt.Errorf("cgroup-v2 %s controller is unavailable in the delegated hierarchy", controller)
		}
		if !containsWord(string(subtree), controller) {
			return nil, fmt.Errorf("cgroup-v2 %s controller is not delegated to the sandbox", controller)
		}
	}

	path, err := filesystem.MkdirTemp(delegatedPath, "sandbox-")
	if err != nil {
		return nil, fmt.Errorf("cgroup-v2 delegation is unavailable: cannot create child cgroup: %v", err)
	}
	limit := &ResourceLimits{path: path, filesystem: filesystem}
	if err := limit.configure(cpuPercent, memoryGB, maxProcesses); err != nil {
		return nil, errors.Join(err, limit.Cleanup())
	}
	return limit, nil
}

func requestedControllers(cpuPercent, memoryGB, maxProcesses int) []string {
	controllers := make([]string, 0, 3)
	if cpuPercent > 0 {
		controllers = append(controllers, "cpu")
	}
	if memoryGB > 0 {
		controllers = append(controllers, "memory")
	}
	if maxProcesses > 0 {
		controllers = append(controllers, "pids")
	}
	return controllers
}

// parseUnifiedCgroupPath extracts the only supported /proc/self/cgroup entry.
// A valid entry has the cgroup-v2 form 0::/relative/path.
func parseUnifiedCgroupPath(reader io.Reader) (string, error) {
	scanner := bufio.NewScanner(reader)
	var (
		path  string
		found bool
	)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Split(line, ":")
		if len(parts) != 3 {
			return "", fmt.Errorf("malformed /proc/self/cgroup entry %q", line)
		}
		if parts[0] != "0" || parts[1] != "" {
			return "", fmt.Errorf("non-v2 cgroup entry %q", line)
		}
		if found {
			return "", fmt.Errorf("duplicate unified cgroup entries")
		}
		candidate := parts[2]
		if candidate == "" || strings.IndexByte(candidate, 0) >= 0 || !filepath.IsAbs(candidate) || filepath.Clean(candidate) != candidate {
			return "", fmt.Errorf("malformed unified cgroup path %q", candidate)
		}
		for _, component := range strings.Split(strings.TrimPrefix(candidate, string(filepath.Separator)), string(filepath.Separator)) {
			if component == "." || component == ".." {
				return "", fmt.Errorf("unified cgroup path %q contains traversal", candidate)
			}
		}
		path = candidate
		found = true
	}
	if err := scanner.Err(); err != nil {
		return "", fmt.Errorf("cannot read /proc/self/cgroup: %v", err)
	}
	if !found {
		return "", fmt.Errorf("unified cgroup entry is missing")
	}
	return path, nil
}

func resolveDelegatedCgroupPath(mountPath, relativePath string) (string, error) {
	if !filepath.IsAbs(mountPath) || !filepath.IsAbs(relativePath) {
		return "", fmt.Errorf("cgroup paths must be absolute")
	}
	if filepath.Clean(relativePath) != relativePath {
		return "", fmt.Errorf("unified cgroup path %q is not canonical", relativePath)
	}

	mountPath = filepath.Clean(mountPath)
	delegatedPath := filepath.Join(mountPath, strings.TrimPrefix(relativePath, string(filepath.Separator)))
	relative, err := filepath.Rel(mountPath, delegatedPath)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("unified cgroup path %q escapes the cgroup mount", relativePath)
	}
	return delegatedPath, nil
}

func (limit *ResourceLimits) configureQuota(percent int) error {
	quota := cgroupCPUPeriod * percent / 100
	if quota <= 0 {
		return fmt.Errorf("cpu limit percent must be greater than zero")
	}
	if err := limit.filesystem.WriteFile(filepath.Join(limit.path, "cpu.max"), []byte(fmt.Sprintf("%d %d\n", quota, cgroupCPUPeriod))); err != nil {
		return fmt.Errorf("cannot configure CPU quota: %v", err)
	}
	return nil
}

func (limit *ResourceLimits) configure(cpuPercent, memoryGB, maxProcesses int) error {
	if cpuPercent > 0 {
		if err := limit.configureQuota(cpuPercent); err != nil {
			return err
		}
	}
	if memoryGB > 0 {
		if uint64(memoryGB) > ^uint64(0)/gbToBytes {
			return fmt.Errorf("memory limit overflows the kernel limit")
		}
		memoryBytes := uint64(memoryGB) * gbToBytes
		if err := limit.filesystem.WriteFile(filepath.Join(limit.path, "memory.max"), []byte(strconv.FormatUint(memoryBytes, 10)+"\n")); err != nil {
			return fmt.Errorf("cannot configure memory limit: %v", err)
		}
	}
	if maxProcesses > 0 {
		if err := limit.filesystem.WriteFile(filepath.Join(limit.path, "pids.max"), []byte(strconv.Itoa(maxProcesses)+"\n")); err != nil {
			return fmt.Errorf("cannot configure process limit: %v", err)
		}
	}
	return nil
}

// Attach moves the child into the already configured resource cgroup.
func (limit *ResourceLimits) Attach(pid int) error {
	if limit == nil {
		return nil
	}
	if pid <= 0 {
		return fmt.Errorf("cannot attach invalid child PID %d to resource cgroup", pid)
	}
	if err := limit.filesystem.WriteFile(filepath.Join(limit.path, "cgroup.procs"), []byte(strconv.Itoa(pid)+"\n")); err != nil {
		return fmt.Errorf("cannot attach child to resource cgroup: %v", err)
	}
	return nil
}

// Cleanup removes the prepared child cgroup. It is safe to call repeatedly.
func (limit *ResourceLimits) Cleanup() error {
	if limit == nil {
		return nil
	}
	limit.mu.Lock()
	defer limit.mu.Unlock()
	if limit.path == "" {
		return nil
	}
	if err := limit.filesystem.Remove(limit.path); err != nil {
		return err
	}
	limit.path = ""
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
