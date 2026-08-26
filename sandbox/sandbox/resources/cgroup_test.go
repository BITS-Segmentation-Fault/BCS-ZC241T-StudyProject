//go:build linux

package resources

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

type fakeCgroupFileSystem struct {
	files       map[string][]byte
	writes      map[string][]byte
	readPaths   []string
	removed     []string
	lastCgroup  string
	mkdirErr    error
	writeErrors map[string]error
	removeErrs  []error
	statfsType  int64
	missing     map[string]bool
}

func newFakeCgroupFileSystem() *fakeCgroupFileSystem {
	return &fakeCgroupFileSystem{
		files:       make(map[string][]byte),
		writes:      make(map[string][]byte),
		writeErrors: make(map[string]error),
		statfsType:  int64(unix.CGROUP2_SUPER_MAGIC),
		missing:     make(map[string]bool),
	}
}

func (f *fakeCgroupFileSystem) ReadFile(path string) ([]byte, error) {
	f.readPaths = append(f.readPaths, path)
	data, ok := f.files[path]
	if !ok {
		return nil, fmt.Errorf("file %q does not exist", path)
	}
	return append([]byte(nil), data...), nil
}

func (f *fakeCgroupFileSystem) MkdirTemp(parent, pattern string) (string, error) {
	if f.mkdirErr != nil {
		return "", f.mkdirErr
	}
	f.lastCgroup = filepath.Join(parent, pattern+"test")
	for _, name := range []string{"cpu.max", "memory.max", "memory.swap.max", "memory.oom.group", "pids.max", "cgroup.procs"} {
		if !f.missing[name] {
			f.files[filepath.Join(f.lastCgroup, name)] = nil
		}
	}
	return f.lastCgroup, nil
}

func (f *fakeCgroupFileSystem) WriteExistingFile(path string, data []byte) error {
	if err := f.writeErrors[filepath.Base(path)]; err != nil {
		return err
	}
	if _, ok := f.files[path]; !ok {
		return fmt.Errorf("file %q does not exist", path)
	}
	f.writes[path] = append([]byte(nil), data...)
	f.files[path] = append([]byte(nil), data...)
	return nil
}

func (f *fakeCgroupFileSystem) Statfs(string) (int64, error) {
	return f.statfsType, nil
}

func (f *fakeCgroupFileSystem) Remove(path string) error {
	if len(f.removeErrs) != 0 {
		err := f.removeErrs[0]
		f.removeErrs = f.removeErrs[1:]
		if err != nil {
			return err
		}
	}
	f.removed = append(f.removed, path)
	for file := range f.files {
		if file == path || strings.HasPrefix(file, path+string(filepath.Separator)) {
			delete(f.files, file)
		}
	}
	return nil
}

func seedDelegatedHierarchy(f *fakeCgroupFileSystem) (procPath, mountPath, delegatedPath string) {
	procPath = "/proc/self/cgroup"
	mountPath = "/sys/fs/cgroup"
	delegatedPath = filepath.Join(mountPath, "user.slice/user-1000.slice/session.scope")
	f.files[procPath] = []byte("0::/user.slice/user-1000.slice/session.scope\n")
	f.files[filepath.Join(delegatedPath, "cgroup.controllers")] = []byte("cpu memory pids\n")
	f.files[filepath.Join(delegatedPath, "cgroup.subtree_control")] = []byte("cpu memory pids\n")
	return procPath, mountPath, delegatedPath
}

func TestParseUnifiedCgroupPath(t *testing.T) {
	tests := []struct {
		name, input, want, wantErr string
	}{
		{"root hierarchy", "0::/\n", "/", ""},
		{"nested hierarchy", "0::/user.slice/session.scope\n", "/user.slice/session.scope", ""},
		{"missing entry", "", "", "missing"},
		{"malformed entry", "0::\n", "", "malformed"},
		{"legacy hierarchy", "1:name=systemd:/user.slice\n", "", "non-v2"},
		{"duplicate unified entries", "0::/one\n0::/two\n", "", "duplicate"},
		{"parent traversal", "0::/user.slice/../etc\n", "", "malformed"},
		{"relative path", "0::user.slice\n", "", "malformed"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseUnifiedCgroupPath(strings.NewReader(tt.input))
			if tt.wantErr == "" {
				if err != nil || got != tt.want {
					t.Fatalf("parseUnifiedCgroupPath() = %q, %v; want %q", got, err, tt.want)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("parseUnifiedCgroupPath() error = %v, want %q", err, tt.wantErr)
			}
		})
	}
}

func TestPrepareResourceLimitsConfiguresAggregateControllers(t *testing.T) {
	fake := newFakeCgroupFileSystem()
	procPath, mountPath, delegatedPath := seedDelegatedHierarchy(fake)
	limit, err := prepareResourceLimits(25, 2, 17, procPath, mountPath, fake)
	if err != nil {
		t.Fatalf("prepareResourceLimits() error = %v", err)
	}
	if limit == nil || !strings.HasPrefix(limit.path, delegatedPath+string(filepath.Separator)) {
		t.Fatalf("prepared cgroup = %#v, want child of %q", limit, delegatedPath)
	}
	for path, want := range map[string]string{
		filepath.Join(limit.path, "cpu.max"):          "25000 100000\n",
		filepath.Join(limit.path, "memory.max"):       "2147483648\n",
		filepath.Join(limit.path, "pids.max"):         "17\n",
		filepath.Join(limit.path, "memory.swap.max"):  "0\n",
		filepath.Join(limit.path, "memory.oom.group"): "1\n",
	} {
		if got := string(fake.writes[path]); got != want {
			t.Errorf("write %s = %q, want %q", path, got, want)
		}
	}
	if err := limit.Attach(1234); err != nil {
		t.Fatalf("Attach() error = %v", err)
	}
	if got := string(fake.writes[filepath.Join(limit.path, "cgroup.procs")]); got != "1234\n" {
		t.Errorf("cgroup.procs = %q, want %q", got, "1234\n")
	}
	if err := limit.Cleanup(); err != nil {
		t.Fatalf("Cleanup() error = %v", err)
	}
	if err := limit.Cleanup(); err != nil {
		t.Fatalf("second Cleanup() error = %v", err)
	}
	if len(fake.removed) != 1 {
		t.Fatalf("removals = %v, want one removal", fake.removed)
	}
}

func TestPrepareResourceLimitsDisabledDoesNotAccessCgroup(t *testing.T) {
	fake := newFakeCgroupFileSystem()
	limit, err := prepareResourceLimits(0, 0, 0, "/missing/proc/self/cgroup", "/missing/cgroup", fake)
	if err != nil || limit != nil {
		t.Fatalf("disabled limits = %#v, %v; want nil, nil", limit, err)
	}
	if len(fake.readPaths) != 0 {
		t.Fatalf("disabled limits read cgroup paths: %v", fake.readPaths)
	}
}

func TestResourceLimitsCleanupRetriesAfterFailure(t *testing.T) {
	fake := newFakeCgroupFileSystem()
	procPath, mountPath, _ := seedDelegatedHierarchy(fake)
	limit, err := prepareResourceLimits(75, 0, 0, procPath, mountPath, fake)
	if err != nil {
		t.Fatalf("prepareResourceLimits() error = %v", err)
	}
	fake.removeErrs = []error{errors.New("busy"), nil}
	if err := limit.Cleanup(); err == nil || !strings.Contains(err.Error(), "busy") {
		t.Fatalf("first Cleanup() error = %v, want busy", err)
	}
	if err := limit.Cleanup(); err != nil {
		t.Fatalf("retry Cleanup() error = %v", err)
	}
	if err := limit.Cleanup(); err != nil {
		t.Fatalf("post-success Cleanup() error = %v", err)
	}
	if len(fake.removed) != 1 {
		t.Fatalf("removals = %v, want one successful removal", fake.removed)
	}
}

func TestResourceLimitsRollbackJoinsCleanupFailure(t *testing.T) {
	fake := newFakeCgroupFileSystem()
	procPath, mountPath, _ := seedDelegatedHierarchy(fake)
	fake.writeErrors["cpu.max"] = errors.New("configure failed")
	fake.removeErrs = []error{errors.New("cleanup failed")}
	_, err := prepareResourceLimits(50, 0, 0, procPath, mountPath, fake)
	if err == nil || !strings.Contains(err.Error(), "configure failed") || !strings.Contains(err.Error(), "cleanup failed") {
		t.Fatalf("prepareResourceLimits() error = %v, want both failures", err)
	}
}

func TestPrepareResourceLimitsRejectsNonCgroupFilesystem(t *testing.T) {
	fake := newFakeCgroupFileSystem()
	fake.statfsType = 0
	procPath, mountPath, _ := seedDelegatedHierarchy(fake)
	if _, err := prepareResourceLimits(50, 0, 0, procPath, mountPath, fake); err == nil || !strings.Contains(err.Error(), "not on a cgroup-v2 filesystem") {
		t.Fatalf("prepareResourceLimits() error = %v, want non-cgroup filesystem error", err)
	}
	if fake.lastCgroup != "" {
		t.Fatal("created a child cgroup on a non-cgroup filesystem")
	}
}

func TestWriteExistingFileDoesNotCreateMissingControl(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cpu.max")
	if err := (osCgroupFileSystem{}).WriteExistingFile(path, []byte("1 100000\n")); err == nil {
		t.Fatal("WriteExistingFile() unexpectedly created a missing control file")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("missing control file stat error = %v, want absent", err)
	}
}

func TestPrepareResourceLimitsRejectsUnavailableControllers(t *testing.T) {
	tests := []struct {
		name, controller, source string
	}{
		{"cpu available list", "cpu", "controllers"},
		{"cpu delegated list", "cpu", "subtree_control"},
		{"memory available list", "memory", "controllers"},
		{"memory delegated list", "memory", "subtree_control"},
		{"pids available list", "pids", "controllers"},
		{"pids delegated list", "pids", "subtree_control"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fake := newFakeCgroupFileSystem()
			procPath, mountPath, delegated := seedDelegatedHierarchy(fake)
			path := filepath.Join(delegated, "cgroup."+tt.source)
			contents := strings.Fields(string(fake.files[path]))
			filtered := contents[:0]
			for _, controller := range contents {
				if controller != tt.controller {
					filtered = append(filtered, controller)
				}
			}
			fake.files[path] = []byte(strings.Join(filtered, " ") + "\n")
			values := map[string][3]int{
				"cpu": {1, 0, 0}, "memory": {0, 1, 0}, "pids": {0, 0, 1},
			}
			value := values[tt.controller]
			if _, err := prepareResourceLimits(value[0], value[1], value[2], procPath, mountPath, fake); err == nil || !strings.Contains(err.Error(), tt.controller+" controller") {
				t.Fatalf("prepareResourceLimits() error = %v, want unavailable %s controller", err, tt.controller)
			}
		})
	}
}

func TestPrepareResourceLimitsFailsWhenControlFileIsUnavailable(t *testing.T) {
	for _, name := range []string{"cpu.max", "memory.max", "memory.swap.max", "memory.oom.group", "pids.max"} {
		t.Run(name, func(t *testing.T) {
			fake := newFakeCgroupFileSystem()
			fake.missing[name] = true
			procPath, mountPath, _ := seedDelegatedHierarchy(fake)
			cpu, memory, pids := 0, 0, 0
			if name == "cpu.max" {
				cpu = 1
			}
			if strings.HasPrefix(name, "memory.") {
				memory = 1
			}
			if name == "pids.max" {
				pids = 1
			}
			_, err := prepareResourceLimits(cpu, memory, pids, procPath, mountPath, fake)
			if err == nil {
				t.Fatalf("prepareResourceLimits() unexpectedly succeeded without %s", name)
			}
			if len(fake.removed) != 1 {
				t.Fatalf("partial cgroup cleanup removals = %v, want one", fake.removed)
			}
			if _, ok := fake.files[filepath.Join(fake.lastCgroup, name)]; ok {
				t.Fatalf("missing control file %s was created", name)
			}
		})
	}
}

func TestPrepareResourceLimitsFailsWhenControlWriteFails(t *testing.T) {
	for _, name := range []string{"cpu.max", "memory.max", "memory.swap.max", "memory.oom.group", "pids.max"} {
		t.Run(name, func(t *testing.T) {
			fake := newFakeCgroupFileSystem()
			fake.writeErrors[name] = errors.New("control write denied")
			procPath, mountPath, _ := seedDelegatedHierarchy(fake)
			cpu, memory, pids := 0, 0, 0
			if name == "cpu.max" {
				cpu = 1
			}
			if strings.HasPrefix(name, "memory.") {
				memory = 1
			}
			if name == "pids.max" {
				pids = 1
			}
			if _, err := prepareResourceLimits(cpu, memory, pids, procPath, mountPath, fake); err == nil {
				t.Fatalf("prepareResourceLimits() unexpectedly succeeded with %s failure", name)
			}
			if len(fake.removed) != 1 {
				t.Fatalf("partial cgroup cleanup removals = %v, want one", fake.removed)
			}
		})
	}
}
