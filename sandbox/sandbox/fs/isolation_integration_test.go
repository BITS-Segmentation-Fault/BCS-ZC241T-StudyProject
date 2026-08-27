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
	if _, err := os.Lstat(filepath.Join(root, "rootfs", "dev")); !os.IsNotExist(err) {
		t.Fatalf("source rootfs /dev changed: %v", err)
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

func TestSynthesizedMountTargets(t *testing.T) {
	if os.Getenv("SANDBOX_FS_TEST") == "synthesized" {
		if err := runSynthesizedMountAssembly(os.Getenv("SANDBOX_FS_ROOT")); err != nil {
			t.Fatal(err)
		}
		return
	}
	requireMountNamespace(t, true)
	root := t.TempDir()
	if err := makeMinimalMountFixture(root); err != nil {
		t.Fatal(err)
	}
	runMountNamespaceTest(t, "synthesized", root)
	for _, path := range []string{"work", "proc", "etc", "ephemeral"} {
		if _, err := os.Lstat(filepath.Join(root, "rootfs", path)); !os.IsNotExist(err) {
			t.Fatalf("synthesized target %q changed source rootfs: %v", path, err)
		}
	}
}

func TestRawOverlayAssembly(t *testing.T) {
	if os.Getenv("SANDBOX_FS_TEST") == "overlay" {
		if err := runRawOverlayAssembly(os.Getenv("SANDBOX_FS_ROOT")); err != nil {
			t.Fatal(err)
		}
		return
	}
	requireMountNamespace(t, false)
	root := t.TempDir()
	if err := makeMinimalMountFixture(root); err != nil {
		t.Fatal(err)
	}
	runMountNamespaceTest(t, "overlay", root)
	for _, path := range []string{"work", "ephemeral"} {
		if _, err := os.Lstat(filepath.Join(root, "rootfs", path)); !os.IsNotExist(err) {
			t.Fatalf("overlay target %q changed source rootfs: %v", path, err)
		}
	}
}

func TestOverlaySetupFailureCleansStaging(t *testing.T) {
	if os.Getenv("SANDBOX_FS_TEST") == "overlay-failure" {
		if err := runOverlaySetupFailure(); err != nil {
			t.Fatal(err)
		}
		return
	}
	requireMountNamespace(t, false)
	runMountNamespaceTest(t, "overlay-failure", "")
}

func TestReadOnlySynthesizedMountTargets(t *testing.T) {
	if os.Getenv("SANDBOX_FS_TEST") == "readonly" {
		if err := runReadOnlySynthesizedMountAssembly(os.Getenv("SANDBOX_FS_ROOT")); err != nil {
			t.Fatal(err)
		}
		return
	}
	requireMountNamespace(t, true)
	root := t.TempDir()
	if err := makeMinimalMountFixture(root); err != nil {
		t.Fatal(err)
	}
	runMountNamespaceTest(t, "readonly", root)
	for _, path := range []string{"work", "license", "writable", "proc", "etc", "root-created"} {
		if _, err := os.Lstat(filepath.Join(root, "rootfs", path)); !os.IsNotExist(err) {
			t.Fatalf("read-only synthesized target %q changed source rootfs: %v", path, err)
		}
	}
	if data, err := os.ReadFile(filepath.Join(root, "source-writable")); err != nil || string(data) != "file-source\n1\n" {
		t.Fatalf("writable bind source = %q, err=%v", data, err)
	}
}

func TestReadOnlyRootKeepsNestedMountReadOnly(t *testing.T) {
	if os.Getenv("SANDBOX_FS_TEST") == "readonly-nested" {
		if err := runReadOnlyRootWithNestedMount(os.Getenv("SANDBOX_FS_ROOT")); err != nil {
			t.Fatal(err)
		}
		return
	}
	requireMountNamespace(t, true)
	root := t.TempDir()
	if err := makeMinimalMountFixture(root); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "rootfs", "nested"), 0755); err != nil {
		t.Fatal(err)
	}
	runMountNamespaceTest(t, "readonly-nested", root)
}

func requireMountNamespace(t *testing.T, needProc bool) {
	t.Helper()
	if _, err := exec.LookPath("unshare"); err != nil {
		skipMountNamespace(t, "unshare is unavailable")
	}
	userNamespace := exec.Command("unshare", "-Ur", "true")
	if output, err := userNamespace.CombinedOutput(); err != nil {
		if isUnavailableUserNamespaceError(output) {
			skipMountNamespace(t, fmt.Sprintf("user namespace prerequisite unavailable: %v\n%s", err, output))
		}
		t.Fatalf("user namespace preflight failed: %v\n%s", err, output)
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

func isUnavailableUserNamespaceError(output []byte) bool {
	message := strings.ToLower(string(output))
	for _, phrase := range []string{"operation not permitted", "permission denied", "read-only file system", "function not implemented"} {
		if strings.Contains(message, phrase) {
			return true
		}
	}
	return false
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
		"assembly":        "TestDescriptorBoundMountAssembly",
		"source":          "TestDescriptorBoundSourceReplacement",
		"target":          "TestDescriptorBoundTargetReplacement",
		"synthesized":     "TestSynthesizedMountTargets",
		"overlay":         "TestRawOverlayAssembly",
		"overlay-failure": "TestOverlaySetupFailureCleansStaging",
		"readonly":        "TestReadOnlySynthesizedMountTargets",
		"readonly-nested": "TestReadOnlyRootKeepsNestedMountReadOnly",
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
	if err := verifyPrivateDeviceFilesystem(); err != nil {
		return err
	}
	for _, path := range []string{"/mnt/new", "/mnt/nested/new"} {
		if err := os.WriteFile(path, []byte("forbidden"), 0600); err == nil {
			return fmt.Errorf("read-only recursive bind allowed write to %s", path)
		}
	}
	return nil
}

func verifyPrivateDeviceFilesystem() error {
	for _, device := range []struct {
		name  string
		major uint32
		minor uint32
	}{
		{name: "null", major: 1, minor: 3},
		{name: "zero", major: 1, minor: 5},
		{name: "full", major: 1, minor: 7},
		{name: "random", major: 1, minor: 8},
		{name: "urandom", major: 1, minor: 9},
	} {
		if err := requireDevicePath(filepath.Join("/dev", device.name), device.major, device.minor); err != nil {
			return err
		}
	}
	if err := verifyNull(); err != nil {
		return err
	}
	if err := verifyZero(); err != nil {
		return err
	}
	if err := verifyFull(); err != nil {
		return err
	}
	if err := verifyRandom(); err != nil {
		return err
	}
	for name, want := range map[string]string{
		"fd":     "/proc/self/fd",
		"stdin":  "/proc/self/fd/0",
		"stdout": "/proc/self/fd/1",
		"stderr": "/proc/self/fd/2",
		"ptmx":   "pts/ptmx",
	} {
		got, err := os.Readlink(filepath.Join("/dev", name))
		if err != nil {
			return fmt.Errorf("readlink /dev/%s: %w", name, err)
		}
		if got != want {
			return fmt.Errorf("/dev/%s -> %q, want %q", name, got, want)
		}
	}
	shm, err := os.Stat("/dev/shm")
	if err != nil {
		return fmt.Errorf("stat /dev/shm: %w", err)
	}
	if !shm.IsDir() || shm.Mode().Perm() != 0777 || shm.Mode()&os.ModeSticky == 0 {
		return fmt.Errorf("/dev/shm mode = %v, want directory 01777", shm.Mode())
	}
	pts, err := os.Stat("/dev/pts")
	if err != nil || !pts.IsDir() {
		return fmt.Errorf("stat /dev/pts: %v, want directory", err)
	}
	if err := requireDevicePath("/dev/pts/ptmx", 5, 2); err != nil {
		return err
	}
	pty, err := unix.Open("/dev/ptmx", unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("open private /dev/ptmx: %w", err)
	}
	if _, err := unix.IoctlGetInt(pty, unix.TIOCGPTN); err != nil {
		_ = unix.Close(pty)
		return fmt.Errorf("private /dev/ptmx did not allocate a PTY: %w", err)
	}
	if err := unix.Close(pty); err != nil {
		return fmt.Errorf("close private /dev/ptmx: %w", err)
	}
	for _, name := range []string{"tty", "console", "kmsg", "sda", "vda", "nvme0n1"} {
		if _, err := os.Lstat(filepath.Join("/dev", name)); err == nil {
			return fmt.Errorf("unrelated /dev/%s is visible", name)
		} else if !os.IsNotExist(err) {
			return fmt.Errorf("check private /dev/%s: %w", name, err)
		}
	}
	entries, err := os.ReadDir("/dev")
	if err != nil {
		return fmt.Errorf("read private /dev: %w", err)
	}
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil {
			return fmt.Errorf("stat private /dev/%s: %w", entry.Name(), err)
		}
		if info.Mode()&os.ModeDevice != 0 && info.Mode()&os.ModeCharDevice == 0 {
			return fmt.Errorf("block device /dev/%s is visible", entry.Name())
		}
	}
	return nil
}

func verifyNull() error {
	fd, err := unix.Open("/dev/null", unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("open /dev/null: %w", err)
	}
	defer unix.Close(fd)
	buffer := make([]byte, 1)
	if n, err := unix.Read(fd, buffer); err != nil || n != 0 {
		return fmt.Errorf("read /dev/null = %d, %v; want EOF", n, err)
	}
	if n, err := unix.Write(fd, []byte("null")); err != nil || n != 4 {
		return fmt.Errorf("write /dev/null = %d, %v; want successful write", n, err)
	}
	return nil
}

func verifyZero() error {
	fd, err := unix.Open("/dev/zero", unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("open /dev/zero: %w", err)
	}
	defer unix.Close(fd)
	buffer := make([]byte, 32)
	n, err := unix.Read(fd, buffer)
	if err != nil || n != len(buffer) {
		return fmt.Errorf("read /dev/zero = %d, %v; want %d zero bytes", n, err, len(buffer))
	}
	for _, value := range buffer {
		if value != 0 {
			return fmt.Errorf("read /dev/zero returned nonzero data")
		}
	}
	return nil
}

func verifyFull() error {
	fd, err := unix.Open("/dev/full", unix.O_WRONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("open /dev/full: %w", err)
	}
	defer unix.Close(fd)
	if _, err := unix.Write(fd, []byte("full")); !errors.Is(err, unix.ENOSPC) {
		return fmt.Errorf("write /dev/full = %v; want ENOSPC", err)
	}
	return nil
}

func verifyRandom() error {
	fd, err := unix.Open("/dev/urandom", unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("open /dev/urandom: %w", err)
	}
	defer unix.Close(fd)
	buffer := make([]byte, 32)
	if n, err := unix.Read(fd, buffer); err != nil || n != len(buffer) {
		return fmt.Errorf("read /dev/urandom = %d, %v; want %d bytes", n, err, len(buffer))
	}
	return nil
}

func requireDevicePath(path string, major, minor uint32) error {
	fd, err := unix.Open(path, unix.O_PATH|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("open %s: %w", path, err)
	}
	defer unix.Close(fd)
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return fmt.Errorf("stat %s: %w", path, err)
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFCHR || unix.Major(stat.Rdev) != major || unix.Minor(stat.Rdev) != minor {
		return fmt.Errorf("%s = mode %#o device %d:%d, want character device %d:%d", path, stat.Mode&unix.S_IFMT, unix.Major(stat.Rdev), unix.Minor(stat.Rdev), major, minor)
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

func runSynthesizedMountAssembly(root string) error {
	rootfs := filepath.Join(root, "rootfs")
	binds := []config.BindMount{
		{HostPath: filepath.Join(root, "source-dir"), ContainerPath: "/work"},
		{HostPath: filepath.Join(root, "source-file"), ContainerPath: "/license"},
	}
	if err := IsolateRootFS(rootfs, binds, false, []string{"1.1.1.1"}); err != nil {
		return err
	}
	if got, err := os.ReadFile("/work/marker"); err != nil || string(got) != "directory-source\n" {
		return fmt.Errorf("synthesized directory bind = %q, err=%v", got, err)
	}
	if got, err := os.ReadFile("/license"); err != nil || string(got) != "file-source\n" {
		return fmt.Errorf("synthesized file bind = %q, err=%v", got, err)
	}
	if got, err := os.ReadFile("/etc/resolv.conf"); err != nil || string(got) != "nameserver 1.1.1.1\n" {
		return fmt.Errorf("synthesized DNS target = %q, err=%v", got, err)
	}
	if _, err := os.ReadFile("/proc/self/status"); err != nil {
		return fmt.Errorf("synthesized proc target is not mounted: %w", err)
	}
	if err := os.WriteFile("/ephemeral", []byte("private\n"), 0600); err != nil {
		return fmt.Errorf("write private root: %w", err)
	}
	return nil
}

func runRawOverlayAssembly(root string) error {
	rootfs := filepath.Join(root, "rootfs")
	if err := unix.Mount("", "/", "", unix.MS_PRIVATE|unix.MS_REC, ""); err != nil {
		return fmt.Errorf("make mount namespace private: %w", err)
	}
	rootFD, err := openSecure(unix.AT_FDCWD, rootfs, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(rootFD)
	overlayFD, stage, err := createOverlayRoot(rootFD)
	if err != nil {
		return err
	}
	defer func() { _ = stage.cleanup() }()
	defer unix.Close(overlayFD)
	if err := moveMount(overlayFD, rootFD); err != nil {
		return fmt.Errorf("attach raw overlay root: %w", err)
	}
	if target, err := openOrCreateTarget(overlayFD, "/work", true); err != nil {
		return err
	} else if err := unix.Close(target); err != nil {
		return err
	}
	if target, err := openOrCreateTarget(overlayFD, "/ephemeral", false); err != nil {
		return err
	} else if err := unix.Close(target); err != nil {
		return err
	}
	if err := setRecursiveMountAttrs(overlayFD, unix.MountAttr{Attr_set: unix.MOUNT_ATTR_NOSUID | unix.MOUNT_ATTR_NODEV}); err != nil {
		return err
	}
	if err := unix.Fchdir(overlayFD); err != nil {
		return err
	}
	if err := os.WriteFile("ephemeral", []byte("private\n"), 0600); err != nil {
		return err
	}
	if err := stage.cleanup(); err != nil {
		return fmt.Errorf("cleanup raw overlay staging: %w", err)
	}
	return nil
}

func runOverlaySetupFailure() error {
	before, err := filepath.Glob(filepath.Join(os.TempDir(), "sandbox-overlay-*"))
	if err != nil {
		return err
	}
	if _, stage, err := createOverlayRoot(-1); err == nil {
		return fmt.Errorf("invalid lower descriptor unexpectedly created an overlay")
	} else if stage != nil {
		return fmt.Errorf("failed overlay returned staging state")
	}
	after, err := filepath.Glob(filepath.Join(os.TempDir(), "sandbox-overlay-*"))
	if err != nil {
		return err
	}
	for _, path := range after {
		found := false
		for _, oldPath := range before {
			if path == oldPath {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("failed overlay left staging directory %q", path)
		}
	}
	return nil
}

func runReadOnlySynthesizedMountAssembly(root string) error {
	rootfs := filepath.Join(root, "rootfs")
	binds := []config.BindMount{
		{HostPath: filepath.Join(root, "source-dir"), ContainerPath: "/work"},
		{HostPath: filepath.Join(root, "source-file"), ContainerPath: "/license"},
		{HostPath: filepath.Join(root, "source-writable"), ContainerPath: "/writable", Writable: true},
	}
	if err := IsolateRootFS(rootfs, binds, true, []string{"1.1.1.1"}); err != nil {
		return err
	}
	if got, err := os.ReadFile("/work/marker"); err != nil || string(got) != "directory-source\n" {
		return fmt.Errorf("read-only synthesized directory bind = %q, err=%v", got, err)
	}
	if got, err := os.ReadFile("/license"); err != nil || string(got) != "file-source\n" {
		return fmt.Errorf("read-only synthesized file bind = %q, err=%v", got, err)
	}
	if got, err := os.ReadFile("/etc/resolv.conf"); err != nil || string(got) != "nameserver 1.1.1.1\n" {
		return fmt.Errorf("read-only synthesized DNS target = %q, err=%v", got, err)
	}
	if _, err := os.ReadFile("/proc/self/status"); err != nil {
		return fmt.Errorf("read-only synthesized proc target is not mounted: %w", err)
	}
	if err := os.WriteFile("/root-created", []byte("forbidden"), 0600); err == nil {
		return fmt.Errorf("read-only root accepted a write")
	}
	file, err := os.OpenFile("/writable", os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		return fmt.Errorf("open writable bind: %w", err)
	}
	if _, err := file.WriteString("1\n"); err != nil {
		_ = file.Close()
		return fmt.Errorf("write writable bind: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close writable bind: %w", err)
	}
	return nil
}

func runReadOnlyRootWithNestedMount(root string) error {
	rootfs := filepath.Join(root, "rootfs")
	nested := filepath.Join(rootfs, "nested")
	if err := unix.Mount("tmpfs", nested, "tmpfs", 0, "size=4096"); err != nil {
		return fmt.Errorf("mount nested rootfs: %w", err)
	}
	if err := os.WriteFile(filepath.Join(nested, "marker"), []byte("nested\n"), 0600); err != nil {
		return err
	}
	if err := IsolateRootFS(rootfs, nil, true, nil); err != nil {
		return err
	}
	if got, err := os.ReadFile("/nested/marker"); err != nil || string(got) != "nested\n" {
		return fmt.Errorf("nested rootfs mount = %q, err=%v", got, err)
	}
	if err := os.WriteFile("/nested/created", []byte("forbidden"), 0600); err == nil {
		return fmt.Errorf("read-only root allowed a nested mount write")
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

func makeMinimalMountFixture(root string) error {
	if err := os.MkdirAll(filepath.Join(root, "rootfs"), 0755); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Join(root, "source-dir"), 0755); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(root, "source-dir", "marker"), []byte("directory-source\n"), 0644); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(root, "source-file"), []byte("file-source\n"), 0644); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(root, "source-writable"), []byte("file-source\n"), 0644)
}

func skipMountNamespace(t *testing.T, reason string) {
	if os.Getenv("SANDBOX_E2E_REQUIRED") == "1" || strings.EqualFold(os.Getenv("SANDBOX_E2E_REQUIRED"), "true") {
		t.Fatalf("required mount namespace prerequisite is unavailable: %s", reason)
	}
	t.Skip(reason)
}
