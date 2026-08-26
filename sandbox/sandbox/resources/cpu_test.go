//go:build linux

package resources

import (
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"
)

type fakeCgroupFileSystem struct {
	files       map[string][]byte
	writes      map[string][]byte
	readPaths   []string
	removed     []string
	lastCgroup  string
	mkdirErr    error
	writeErrors map[string]error
	removeErr   error
}

func newFakeCgroupFileSystem() *fakeCgroupFileSystem {
	return &fakeCgroupFileSystem{
		files:       make(map[string][]byte),
		writes:      make(map[string][]byte),
		writeErrors: make(map[string]error),
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
	f.files[filepath.Join(f.lastCgroup, "cpu.max")] = nil
	f.files[filepath.Join(f.lastCgroup, "cgroup.procs")] = nil
	return f.lastCgroup, nil
}

func (f *fakeCgroupFileSystem) WriteFile(path string, data []byte, _ fs.FileMode) error {
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

func (f *fakeCgroupFileSystem) Remove(path string) error {
	if f.removeErr != nil {
		return f.removeErr
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
	f.files[filepath.Join(delegatedPath, "cgroup.controllers")] = []byte("cpu memory\n")
	f.files[filepath.Join(delegatedPath, "cgroup.subtree_control")] = []byte("cpu\n")
	return procPath, mountPath, delegatedPath
}

func TestParseUnifiedCgroupPath(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr string
	}{
		{name: "root hierarchy", input: "0::/\n", want: "/"},
		{name: "nested hierarchy", input: "0::/user.slice/user-1000.slice/session.scope\n", want: "/user.slice/user-1000.slice/session.scope"},
		{name: "missing entry", input: "", wantErr: "missing"},
		{name: "malformed entry", input: "0::\n", wantErr: "malformed"},
		{name: "legacy hierarchy", input: "1:name=systemd:/user.slice\n", wantErr: "non-v2"},
		{name: "duplicate unified entries", input: "0::/one\n0::/two\n", wantErr: "duplicate"},
		{name: "parent traversal", input: "0::/user.slice/../etc\n", wantErr: "malformed"},
		{name: "relative path", input: "0::user.slice\n", wantErr: "malformed"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseUnifiedCgroupPath(strings.NewReader(tt.input))
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("parseUnifiedCgroupPath() error = %v", err)
				}
				if got != tt.want {
					t.Fatalf("parseUnifiedCgroupPath() = %q, want %q", got, tt.want)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("parseUnifiedCgroupPath() error = %v, want %q", err, tt.wantErr)
			}
		})
	}
}

func TestPrepareCPULimitDisabledDoesNotAccessCgroup(t *testing.T) {
	fake := newFakeCgroupFileSystem()
	limit, err := prepareCPULimit(0, "/missing/proc/self/cgroup", "/missing/cgroup", fake)
	if err != nil {
		t.Fatalf("prepareCPULimit() error = %v", err)
	}
	if limit != nil {
		t.Fatal("prepareCPULimit() returned a handle for a disabled limit")
	}
	if len(fake.readPaths) != 0 {
		t.Fatalf("disabled CPU limit read cgroup paths: %v", fake.readPaths)
	}
}

func TestPrepareCPULimitConfiguresAttachesAndCleansUp(t *testing.T) {
	fake := newFakeCgroupFileSystem()
	procPath, mountPath, delegatedPath := seedDelegatedHierarchy(fake)

	limit, err := prepareCPULimit(25, procPath, mountPath, fake)
	if err != nil {
		t.Fatalf("prepareCPULimit() error = %v", err)
	}
	if limit == nil {
		t.Fatal("prepareCPULimit() returned nil handle")
	}
	if got, want := string(fake.writes[filepath.Join(limit.path, "cpu.max")]), "25000 100000\n"; got != want {
		t.Fatalf("cpu.max = %q, want %q", got, want)
	}
	if !strings.HasPrefix(limit.path, delegatedPath+string(filepath.Separator)) {
		t.Fatalf("cgroup %q was not created beneath delegated path %q", limit.path, delegatedPath)
	}
	if err := limit.Attach(1234); err != nil {
		t.Fatalf("Attach() error = %v", err)
	}
	if got, want := string(fake.writes[filepath.Join(limit.path, "cgroup.procs")]), "1234\n"; got != want {
		t.Fatalf("cgroup.procs = %q, want %q", got, want)
	}
	if err := limit.Cleanup(); err != nil {
		t.Fatalf("Cleanup() error = %v", err)
	}
	if err := limit.Cleanup(); err != nil {
		t.Fatalf("second Cleanup() error = %v", err)
	}
	if len(fake.removed) != 1 || fake.removed[0] != limit.path {
		t.Fatalf("removed cgroups = %v, want one removal of %q", fake.removed, limit.path)
	}
}

func TestPrepareCPULimitRejectsUnavailableDelegation(t *testing.T) {
	tests := []struct {
		name    string
		setup   func(*fakeCgroupFileSystem)
		wantErr string
	}{
		{
			name: "missing controllers",
			setup: func(f *fakeCgroupFileSystem) {
				_, _, delegated := seedDelegatedHierarchy(f)
				delete(f.files, filepath.Join(delegated, "cgroup.controllers"))
			},
			wantErr: "CPU controller is unavailable",
		},
		{
			name: "controller not delegated",
			setup: func(f *fakeCgroupFileSystem) {
				_, _, delegated := seedDelegatedHierarchy(f)
				f.files[filepath.Join(delegated, "cgroup.subtree_control")] = []byte("memory\n")
			},
			wantErr: "not delegated",
		},
		{
			name: "mkdir failure",
			setup: func(f *fakeCgroupFileSystem) {
				seedDelegatedHierarchy(f)
				f.mkdirErr = errors.New("read-only hierarchy")
			},
			wantErr: "cannot create child cgroup",
		},
		{
			name: "quota failure rolls back",
			setup: func(f *fakeCgroupFileSystem) {
				seedDelegatedHierarchy(f)
				f.writeErrors["cpu.max"] = errors.New("permission denied")
			},
			wantErr: "cannot configure CPU quota",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fake := newFakeCgroupFileSystem()
			tt.setup(fake)
			limit, err := prepareCPULimit(50, "/proc/self/cgroup", "/sys/fs/cgroup", fake)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("prepareCPULimit() error = %v, want %q", err, tt.wantErr)
			}
			if limit != nil {
				t.Fatal("prepareCPULimit() returned a handle after failure")
			}
			if tt.name == "quota failure rolls back" && len(fake.removed) != 1 {
				t.Fatalf("failed quota setup removed %d cgroups, want 1", len(fake.removed))
			}
		})
	}
}

func TestCPULimitAttachFailureStillCleansUp(t *testing.T) {
	fake := newFakeCgroupFileSystem()
	procPath, mountPath, _ := seedDelegatedHierarchy(fake)
	limit, err := prepareCPULimit(75, procPath, mountPath, fake)
	if err != nil {
		t.Fatalf("prepareCPULimit() error = %v", err)
	}
	fake.writeErrors["cgroup.procs"] = errors.New("attach denied")
	if err := limit.Attach(1234); err == nil {
		t.Fatal("Attach() unexpectedly succeeded")
	}
	if err := limit.Cleanup(); err != nil {
		t.Fatalf("Cleanup() error = %v", err)
	}
	if len(fake.removed) != 1 {
		t.Fatalf("removed cgroups = %v, want one removal", fake.removed)
	}
}

func TestCPULimitCleanupReportsFailure(t *testing.T) {
	fake := newFakeCgroupFileSystem()
	procPath, mountPath, _ := seedDelegatedHierarchy(fake)
	limit, err := prepareCPULimit(75, procPath, mountPath, fake)
	if err != nil {
		t.Fatalf("prepareCPULimit() error = %v", err)
	}
	fake.removeErr = errors.New("busy")
	if err := limit.Cleanup(); err == nil || !strings.Contains(err.Error(), "busy") {
		t.Fatalf("Cleanup() error = %v, want busy", err)
	}
}
