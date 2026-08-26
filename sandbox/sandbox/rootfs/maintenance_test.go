//go:build linux

package rootfs

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// This test intentionally contacts Alpine's pinned release infrastructure.
// It is excluded from hermetic and default CI; the reviewed archive and tree
// digests are checked into releaseCatalog after this test is run.
func TestPinnedAlpineArchives(t *testing.T) {
	if os.Getenv("SANDBOX_ALPINE_MAINTENANCE") != "1" {
		t.Skip("official Alpine maintenance test requires SANDBOX_ALPINE_MAINTENANCE=1")
	}
	for _, goArch := range []string{"amd64", "arm64"} {
		t.Run(goArch, func(t *testing.T) {
			release, err := releaseInfoFor(goArch)
			if err != nil {
				t.Fatal(err)
			}
			archivePath := filepath.Join(t.TempDir(), release.ArchiveName)
			if err := (Provisioner{}).download(context.Background(), release, archivePath); err != nil {
				t.Fatal(err)
			}
			root := filepath.Join(t.TempDir(), "rootfs")
			if err := os.Mkdir(root, 0700); err != nil {
				t.Fatal(err)
			}
			if err := extractArchive(archivePath, root, defaultRootfsLimits); err != nil {
				t.Fatal(err)
			}
			if err := validateRootfsLayout(root); err != nil {
				t.Fatal(err)
			}
			got, err := treeDigest(root)
			if err != nil {
				t.Fatal(err)
			}
			if got != release.TreeSHA256 {
				t.Fatalf("tree SHA-256 = %s, want %s", got, release.TreeSHA256)
			}
		})
	}
}
