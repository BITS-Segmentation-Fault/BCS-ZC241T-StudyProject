//go:build linux

package fs

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"sandbox/sandbox/config"

	"golang.org/x/sys/unix"
)

const mountProbeUnavailableExit = 77

type unavailableMountAPIError struct {
	operation string
	err       error
}

func (e *unavailableMountAPIError) Error() string {
	return fmt.Sprintf("mount API unavailable: %s: %v", e.operation, e.err)
}

func (e *unavailableMountAPIError) Unwrap() error {
	return e.err
}

func classifyMountAPIError(operation string, err error) error {
	if errors.Is(err, unix.ENOSYS) || errors.Is(err, unix.EOPNOTSUPP) || errors.Is(err, unix.EPERM) {
		return &unavailableMountAPIError{operation: operation, err: err}
	}
	return fmt.Errorf("%s: %w", operation, err)
}

func TestMountNamespaceProbe(t *testing.T) {
	if os.Getenv("SANDBOX_FS_PROBE") != "1" {
		return
	}
	if err := runMountNamespaceProbe(os.Getenv("SANDBOX_FS_PROBE_PROC") == "1"); err != nil {
		if isUnavailableMountProbeError(err) {
			fmt.Fprintln(os.Stderr, "mount API prerequisite unavailable:", err)
			os.Exit(mountProbeUnavailableExit)
		}
		t.Fatal(err)
	}
}

func TestDescriptorBoundMountAssembly(t *testing.T) {
	if os.Getenv("SANDBOX_FS_TEST") == "assembly" {
		if err := runDescriptorBoundMountAssembly(os.Getenv("SANDBOX_FS_ROOT")); err != nil {
			t.Fatal(err)
		}
		return
	}
	requireMountNamespace(t, true)
	root := t.TempDir()
	if err := makeMountFixture(root); err != nil {
		t.Fatal(err)
	}
	runMountNamespaceTest(t, "assembly", root)
	if got, err := os.ReadFile(filepath.Join(root, "rootfs", "etc", "resolv.conf")); err != nil {
		t.Fatal(err)
	} else if string(got) != "original\n" {
		t.Fatalf("source rootfs resolv.conf changed: %q", got)
	}
}

func TestDescriptorBoundSourceReplacement(t *testing.T) {
	if os.Getenv("SANDBOX_FS_TEST") == "source" {
		if err := runSourceReplacement(os.Getenv("SANDBOX_FS_ROOT")); err != nil {
			t.Fatal(err)
		}
		return
	}
	requireMountNamespace(t, false)
	root := t.TempDir()
	if err := makeMountFixture(root); err != nil {
		t.Fatal(err)
	}
	runMountNamespaceTest(t, "source", root)
}

func TestDescriptorBoundTargetReplacement(t *testing.T) {
	if os.Getenv("SANDBOX_FS_TEST") == "target" {
		if err := runTargetReplacement(os.Getenv("SANDBOX_FS_ROOT")); err != nil {
			t.Fatal(err)
		}
		return
	}
	requireMountNamespace(t, false)
	root := t.TempDir()
	if err := makeMountFixture(root); err != nil {
		t.Fatal(err)
	}
	runMountNamespaceTest(t, "target", root)
}

func requireMountNamespace(t *testing.T, needProc bool) {
	t.Helper()
	if _, err := exec.LookPath("unshare"); err != nil {
		skipMountNamespace(t, "unshare is unavailable")
	}
	userNamespace := exec.Command("unshare", "-Ur", "true")
	if output, err := userNamespace.CombinedOutput(); err != nil {
		skipMountNamespace(t, fmt.Sprintf("user namespace preflight failed: %v\n%s", err, output))
	}
	command := exec.Command("unshare", "-Urnm", "--", os.Args[0], "-test.run=^TestMountNamespaceProbe$")
	probeProc := "0"
	if needProc {
		probeProc = "1"
	}
	command.Env = append(os.Environ(), "SANDBOX_FS_PROBE=1", "SANDBOX_FS_PROBE_PROC="+probeProc)
	output, err := command.CombinedOutput()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == mountProbeUnavailableExit {
			skipMountNamespace(t, fmt.Sprintf("mount API prerequisite unavailable: %s", output))
		}
		t.Fatalf("mount API probe failed: %v\n%s", err, output)
	}
}

func isUnavailableMountProbeError(err error) bool {
	var unavailable *unavailableMountAPIError
	return errors.As(err, &unavailable)
}

func TestMountAPIErrorClassification(t *testing.T) {
	for _, errno := range []unix.Errno{unix.EPERM, unix.ENOSYS, unix.EOPNOTSUPP} {
		if err := classifyMountAPIError("test operation", errno); !isUnavailableMountProbeError(err) {
			t.Errorf("classifyMountAPIError(%v) = %v, want unavailable", errno, err)
		}
	}
	if err := fmt.Errorf("fixture setup: %w", unix.EPERM); isUnavailableMountProbeError(err) {
		t.Fatalf("ordinary fixture error was classified as unavailable: %v", err)
	}
	if err := classifyMountAPIError("test operation", unix.EINVAL); isUnavailableMountProbeError(err) {
		t.Fatalf("EINVAL was classified as unavailable: %v", err)
	}
}

func runMountNamespaceTest(t *testing.T, mode, root string) {
	t.Helper()
	testName := map[string]string{
		"assembly": "TestDescriptorBoundMountAssembly",
		"source":   "TestDescriptorBoundSourceReplacement",
		"target":   "TestDescriptorBoundTargetReplacement",
	}[mode]
	command := exec.Command("unshare", "-Urnm", "--", os.Args[0], "-test.run=^"+testName+"$")
	command.Env = append(os.Environ(), "SANDBOX_FS_TEST="+mode, "SANDBOX_FS_ROOT="+root)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("descriptor-bound %s test failed: %v\n%s", mode, err, output)
	}
}

func runMountNamespaceProbe(needProc bool) error {
	if err := unix.Mount("", "/", "", unix.MS_PRIVATE|unix.MS_REC, ""); err != nil {
		return classifyMountAPIError("make mount namespace private", err)
	}
	fixture, err := os.MkdirTemp(os.TempDir(), "sandbox-mount-probe-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(fixture)
	if err := os.Mkdir(filepath.Join(fixture, "source"), 0755); err != nil {
		return err
	}
	if err := os.Mkdir(filepath.Join(fixture, "target"), 0755); err != nil {
		return err
	}
	rootFD, err := unix.Open(fixture, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("open mount API probe root: %w", err)
	}
	defer unix.Close(rootFD)
	rootMount, err := unix.OpenTree(rootFD, "", uint(unix.OPEN_TREE_CLONE|unix.OPEN_TREE_CLOEXEC|unix.AT_EMPTY_PATH|unix.AT_RECURSIVE))
	if err != nil {
		return classifyMountAPIError("open_tree root", err)
	}
	defer unix.Close(rootMount)
	if err := unix.MountSetattr(rootMount, "", unix.AT_EMPTY_PATH|unix.AT_RECURSIVE, &unix.MountAttr{}); err != nil {
		return classifyMountAPIError("mount_setattr", err)
	}
	if err := unix.MoveMount(rootMount, "", rootFD, "", unix.MOVE_MOUNT_F_EMPTY_PATH|unix.MOVE_MOUNT_T_EMPTY_PATH); err != nil {
		return classifyMountAPIError("move_mount root", err)
	}
	source, err := unix.Open(filepath.Join(fixture, "source"), unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(source)
	target, err := unix.Openat2(rootMount, "target", &unix.OpenHow{Flags: unix.O_PATH | unix.O_CLOEXEC, Resolve: unix.RESOLVE_BENEATH | secureResolve})
	if err != nil {
		return classifyMountAPIError("openat2 target", err)
	}
	defer unix.Close(target)
	mountFD, err := unix.OpenTree(source, "", uint(unix.OPEN_TREE_CLONE|unix.OPEN_TREE_CLOEXEC|unix.AT_EMPTY_PATH|unix.AT_RECURSIVE))
	if err != nil {
		return classifyMountAPIError("open_tree source", err)
	}
	defer unix.Close(mountFD)
	if err := unix.MoveMount(mountFD, "", target, "", unix.MOVE_MOUNT_F_EMPTY_PATH|unix.MOVE_MOUNT_T_EMPTY_PATH); err != nil {
		return classifyMountAPIError("move_mount child", err)
	}
	if !needProc {
		return nil
	}
	procContext, err := unix.Fsopen("proc", unix.FSOPEN_CLOEXEC)
	if err != nil {
		return classifyMountAPIError("fsopen proc", err)
	}
	defer unix.Close(procContext)
	if err := unix.FsconfigCreate(procContext); err != nil {
		return classifyMountAPIError("fsconfig proc", err)
	}
	procMount, err := unix.Fsmount(procContext, unix.FSMOUNT_CLOEXEC, 0)
	if err != nil {
		return classifyMountAPIError("fsmount proc", err)
	}
	defer unix.Close(procMount)
	return nil
}

func runDescriptorBoundMountAssembly(root string) error {
	rootfs := filepath.Join(root, "rootfs")
	source := filepath.Join(root, "source")
	if err := unix.Mount("tmpfs", filepath.Join(source, "nested"), "tmpfs", 0, "size=4096"); err != nil {
		return fmt.Errorf("mount nested source: %w", err)
	}
	if err := os.WriteFile(filepath.Join(source, "nested", "marker"), []byte("nested\n"), 0600); err != nil {
		return err
	}
	binds := []config.BindMount{{HostPath: source, ContainerPath: "/mnt"}}
	if err := IsolateRootFS(rootfs, binds, true, []string{"1.1.1.1", "2001:4860:4860::8888"}); err != nil {
		return err
	}
	if got, err := os.ReadFile("/mnt/bound"); err != nil || string(got) != "opened-source\n" {
		return fmt.Errorf("bind content = %q, err=%v", got, err)
	}
	if got, err := os.ReadFile("/mnt/nested/marker"); err != nil || string(got) != "nested\n" {
		return fmt.Errorf("recursive bind content = %q, err=%v", got, err)
	}
	if got, err := os.ReadFile("/etc/resolv.conf"); err != nil || string(got) != "nameserver 1.1.1.1\nnameserver 2001:4860:4860::8888\n" {
		return fmt.Errorf("DNS content = %q, err=%v", got, err)
	}
	if _, err := os.ReadFile("/proc/self/status"); err != nil {
		return fmt.Errorf("proc attachment failed: %w", err)
	}
	for _, path := range []string{"/mnt/new", "/mnt/nested/new"} {
		if err := os.WriteFile(path, []byte("forbidden"), 0600); err == nil {
			return fmt.Errorf("read-only recursive bind allowed write to %s", path)
		}
	}
	return nil
}

func runSourceReplacement(root string) error {
	rootfs := filepath.Join(root, "rootfs")
	sourcePath := filepath.Join(root, "source")
	if err := unix.Mount("", "/", "", unix.MS_PRIVATE|unix.MS_REC, ""); err != nil {
		return fmt.Errorf("make mount namespace private: %w", err)
	}
	rootFD, err := openSecure(unix.AT_FDCWD, rootfs, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(rootFD)
	rootMount, err := cloneMount(rootFD, true)
	if err != nil {
		return err
	}
	defer unix.Close(rootMount)
	if err := moveMount(rootMount, rootFD); err != nil {
		return fmt.Errorf("attach rootfs mount: %w", err)
	}
	source, isDir, err := openBindSource(sourcePath)
	if err != nil {
		return err
	}
	defer unix.Close(source)
	if err := os.Rename(sourcePath, filepath.Join(root, "source-replaced")); err != nil {
		return err
	}
	if err := os.Mkdir(sourcePath, 0755); err != nil {
		return err
	}
	target, err := openTarget(rootMount, "/mnt")
	if err != nil {
		return err
	}
	defer unix.Close(target)
	if err := attachBindMount(rootMount, target, config.BindMount{HostPath: sourcePath, ContainerPath: "/mnt"}, source, isDir); err != nil {
		return err
	}
	data, err := readAt(rootMount, "mnt/bound")
	if err != nil {
		return err
	}
	if string(data) != "opened-source\n" {
		return fmt.Errorf("source replacement mounted %q", data)
	}
	return nil
}

func runTargetReplacement(root string) error {
	rootfs := filepath.Join(root, "rootfs")
	sourcePath := filepath.Join(root, "source")
	if err := unix.Mount("", "/", "", unix.MS_PRIVATE|unix.MS_REC, ""); err != nil {
		return fmt.Errorf("make mount namespace private: %w", err)
	}
	rootFD, err := openSecure(unix.AT_FDCWD, rootfs, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(rootFD)
	rootMount, err := cloneMount(rootFD, true)
	if err != nil {
		return err
	}
	defer unix.Close(rootMount)
	if err := moveMount(rootMount, rootFD); err != nil {
		return fmt.Errorf("attach rootfs mount: %w", err)
	}
	source, isDir, err := openBindSource(sourcePath)
	if err != nil {
		return err
	}
	defer unix.Close(source)
	target, err := openTarget(rootMount, "/mnt")
	if err != nil {
		return err
	}
	defer unix.Close(target)
	if err := os.Rename(filepath.Join(rootfs, "mnt"), filepath.Join(rootfs, "mnt-replaced")); err != nil {
		return err
	}
	if err := os.Mkdir(filepath.Join(rootfs, "mnt"), 0755); err != nil {
		return err
	}
	err = attachBindMount(rootMount, target, config.BindMount{HostPath: sourcePath, ContainerPath: "/mnt"}, source, isDir)
	if err == nil || !strings.Contains(err.Error(), "does not resolve to its mounted source") {
		return fmt.Errorf("target replacement error = %v", err)
	}
	return nil
}

func readAt(rootFD int, path string) ([]byte, error) {
	how := &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_CLOEXEC, Resolve: beneathResolve}
	fd, err := unix.Openat2(rootFD, path, how)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	return io.ReadAll(file)
}

func makeMountFixture(root string) error {
	for _, directory := range []string{
		filepath.Join(root, "rootfs", "etc"),
		filepath.Join(root, "rootfs", "mnt"),
		filepath.Join(root, "rootfs", "proc"),
		filepath.Join(root, "source", "nested"),
	} {
		if err := os.MkdirAll(directory, 0755); err != nil {
			return err
		}
	}
	if err := os.WriteFile(filepath.Join(root, "rootfs", "etc", "resolv.conf"), []byte("original\n"), 0644); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(root, "source", "bound"), []byte("opened-source\n"), 0644)
}

func skipMountNamespace(t *testing.T, reason string) {
	if os.Getenv("SANDBOX_E2E_REQUIRED") == "1" || strings.EqualFold(os.Getenv("SANDBOX_E2E_REQUIRED"), "true") {
		t.Fatalf("required mount namespace prerequisite is unavailable: %s", reason)
	}
	t.Skip(reason)
}
