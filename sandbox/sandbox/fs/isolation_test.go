//go:build linux

package fs

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestSafePathRejectsTraversalAndSymlinkComponents(t *testing.T) {
	if !hasParentComponent("/root/../outside") {
		t.Fatal("parent traversal was not detected")
	}
	if hasParentComponent("/root/inside") {
		t.Fatal("ordinary path was rejected")
	}

	root := t.TempDir()
	target := filepath.Join(root, "target")
	if err := os.Symlink("/", target); err != nil {
		t.Fatal(err)
	}
	if _, err := openSecure(unix.AT_FDCWD, target, unix.O_PATH|unix.O_CLOEXEC, 0, false); err == nil {
		t.Fatal("openSecure followed a symlink")
	}
}

func TestEnsurePathRejectsBindTypeMismatch(t *testing.T) {
	root := t.TempDir()
	rootFD, err := unix.Open(root, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(rootFD)

	source := filepath.Join(root, "source")
	if err := os.WriteFile(source, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	sourceFD, err := unix.Open(source, unix.O_PATH|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(sourceFD)

	if err := ensureBindTarget(rootFD, "/target", sourceFD); err != nil {
		t.Fatalf("ensureBindTarget() creating file = %v", err)
	}
	if err := ensureBindTarget(rootFD, "/target", sourceFD); err != nil {
		t.Fatalf("ensureBindTarget() reopening file = %v", err)
	}
	if err := ensureDirectory(rootFD, "/target"); err == nil {
		t.Fatal("ensureDirectory accepted a regular-file target")
	}
}
