//go:build linux

package fs

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestOpenSecureRejectsSymlinkComponents(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target")
	if err := os.Symlink("/", target); err != nil {
		t.Fatal(err)
	}
	if _, err := openSecure(unix.AT_FDCWD, target, unix.O_PATH|unix.O_CLOEXEC, 0); err == nil {
		t.Fatal("openSecure followed a symlink")
	}
}

func TestOpenTargetRejectsUnsafePaths(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "outside"), []byte("outside"), 0644); err != nil {
		t.Fatal(err)
	}
	rootFD, err := unix.Open(root, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(rootFD)
	for _, path := range []string{"/", "/../outside", "/missing"} {
		if fd, err := openTarget(rootFD, path); err == nil {
			_ = unix.Close(fd)
			t.Errorf("openTarget(%q) unexpectedly succeeded", path)
		}
	}
}

func TestValidateIsolationPathRejectsUnsafeBindPaths(t *testing.T) {
	for _, test := range []struct {
		name string
		path string
	}{
		{name: "empty", path: ""},
		{name: "relative", path: "relative/path"},
		{name: "nul", path: "/tmp\x00file"},
		{name: "parent", path: "/tmp/../file"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := validateIsolationPath("bind path", test.path); err == nil {
				t.Fatalf("validateIsolationPath(%q) accepted unsafe path", test.path)
			}
		})
	}
}

func TestOpenTargetRejectsSymlinkAndAcceptsExistingTarget(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "etc"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "etc", "target"), []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/", filepath.Join(root, "etc", "link")); err != nil {
		t.Fatal(err)
	}
	rootFD, err := unix.Open(root, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(rootFD)
	fd, err := openTarget(rootFD, "/etc/target")
	if err != nil {
		t.Fatal(err)
	}
	unix.Close(fd)
	if fd, err := openTarget(rootFD, "/etc/link"); err == nil {
		unix.Close(fd)
		t.Fatal("openTarget followed a symlink")
	}
}

func TestOpenOrCreateTargetCreatesOnlyRelativeTargets(t *testing.T) {
	root := t.TempDir()
	rootFD, err := unix.Open(root, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(rootFD)

	directory, err := openOrCreateTarget(rootFD, "/etc/work", true)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(directory)
	file, err := openOrCreateTarget(rootFD, "/etc/resolv.conf", false)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(file)
	if _, err := os.Stat(filepath.Join(root, "etc", "work")); err != nil {
		t.Fatalf("created directory is missing: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "etc", "resolv.conf")); err != nil {
		t.Fatalf("created file is missing: %v", err)
	}
}

func TestOpenOrCreateTargetRejectsSymlinkedParent(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(root, "etc")); err != nil {
		t.Fatal(err)
	}
	rootFD, err := unix.Open(root, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(rootFD)
	if _, err := openOrCreateTarget(rootFD, "/etc/work", true); err == nil {
		t.Fatal("openOrCreateTarget followed a symlink")
	}
}

func TestRequireSameType(t *testing.T) {
	root := t.TempDir()
	sourcePath := filepath.Join(root, "source")
	targetPath := filepath.Join(root, "target")
	if err := os.WriteFile(sourcePath, []byte("source"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(targetPath, 0755); err != nil {
		t.Fatal(err)
	}
	source, err := unix.Open(sourcePath, unix.O_PATH|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(source)
	target, err := unix.Open(targetPath, unix.O_PATH|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(target)
	err = requireSameType(source, target, sourcePath, targetPath)
	if err == nil || !strings.Contains(err.Error(), "type does not match") {
		t.Fatalf("requireSameType() = %v, want type mismatch", err)
	}
}

func TestRequireSameTypeRejectsUnsupportedSource(t *testing.T) {
	root := t.TempDir()
	sourcePath := filepath.Join(root, "socket")
	if err := unix.Mkfifo(sourcePath, 0600); err != nil {
		t.Fatal(err)
	}
	targetPath := filepath.Join(root, "target")
	if err := unix.Mkfifo(targetPath, 0600); err != nil {
		t.Fatal(err)
	}
	source, err := unix.Open(sourcePath, unix.O_PATH|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(source)
	target, err := unix.Open(targetPath, unix.O_PATH|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(target)
	if err := requireSameType(source, target, sourcePath, targetPath); err == nil {
		t.Fatal("requireSameType accepted a FIFO")
	}
}

func TestDNSMemfdIsCompleteAndSealed(t *testing.T) {
	fd, err := makeDNSMemfd([]string{"1.1.1.1", "2001:4860:4860::8888"})
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	data := make([]byte, 128)
	n, err := unix.Pread(fd, data, 0)
	if err != nil {
		t.Fatal(err)
	}
	got := string(data[:n])
	want := "nameserver 1.1.1.1\nnameserver 2001:4860:4860::8888\n"
	if got != want {
		t.Fatalf("DNS contents = %q, want %q", got, want)
	}
	seals, err := unix.FcntlInt(uintptr(fd), unix.F_GET_SEALS, 0)
	if err != nil {
		t.Fatal(err)
	}
	required := unix.F_SEAL_SEAL | unix.F_SEAL_SHRINK | unix.F_SEAL_GROW | unix.F_SEAL_WRITE
	if seals&required != required {
		t.Fatalf("DNS seals = %#x, want %#x", seals, required)
	}
}

func TestOverlayStageCleanupIsRepeatable(t *testing.T) {
	path := t.TempDir()
	fd, err := unix.Open(path, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	stage := &overlayStage{path: path, stageFD: fd, upperFD: -1, workFD: -1, lowerFD: -1, stagingMount: -1}
	if err := stage.cleanup(); err != nil {
		t.Fatal(err)
	}
	if stage.path != "" || stage.stageFD != -1 {
		t.Fatalf("cleanup left stage state: %+v", stage)
	}
	if err := stage.cleanup(); err != nil {
		t.Fatalf("second cleanup failed: %v", err)
	}
}

func TestOverlayStageCleanupDoesNotReuseClosedDescriptor(t *testing.T) {
	path := t.TempDir()
	if err := os.WriteFile(filepath.Join(path, "busy"), []byte("busy"), 0600); err != nil {
		t.Fatal(err)
	}
	fd, err := unix.Open(path, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	stage := &overlayStage{path: path, stageFD: fd, upperFD: -1, workFD: -1, lowerFD: -1, stagingMount: -1}
	if err := stage.cleanup(); err == nil {
		t.Fatal("cleanup unexpectedly removed a non-empty staging directory")
	}
	if stage.stageFD != -1 {
		t.Fatalf("cleanup retained a descriptor after taking ownership: %d", stage.stageFD)
	}

	openFD, err := unix.Open("/dev/null", unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(openFD)
	if err := os.Remove(filepath.Join(path, "busy")); err != nil {
		t.Fatal(err)
	}
	if err := stage.cleanup(); err != nil {
		t.Fatalf("cleanup retry failed: %v", err)
	}
	if err := unix.Fstat(openFD, &unix.Stat_t{}); err != nil {
		t.Fatalf("cleanup closed an unrelated descriptor: %v", err)
	}
}

func TestTrustedDeviceSourcesConditionallyIncludeTTY(t *testing.T) {
	nonInteractive := trustedDeviceSources(false)
	interactive := trustedDeviceSources(true)
	if len(interactive) != len(nonInteractive)+1 {
		t.Fatalf("interactive source count = %d, noninteractive = %d", len(interactive), len(nonInteractive))
	}
	for _, device := range nonInteractive {
		if device.name == "tty" {
			t.Fatal("noninteractive device sources include tty")
		}
	}
	if got := interactive[len(interactive)-1]; got.name != "tty" || got.path != "/dev/tty" || got.major != 5 || got.minor != 0 {
		t.Fatalf("interactive tty source = %+v", got)
	}
}
