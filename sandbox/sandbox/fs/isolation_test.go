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
