//go:build linux

package rootfs

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// This test intentionally contacts Alpine's pinned release infrastructure.
// It is excluded from hermetic and default CI; the reviewed archive digests
// are checked into the default managed source after this test is run.
func TestPinnedAlpineArchives(t *testing.T) {
	if os.Getenv("SANDBOX_ALPINE_MAINTENANCE") != "1" {
		t.Skip("official Alpine maintenance test requires SANDBOX_ALPINE_MAINTENANCE=1")
	}
	for goArch, release := range defaultManagedSource.Releases {
		t.Run(goArch, func(t *testing.T) {
			archivePath := filepath.Join(t.TempDir(), release.ArchiveName)
			if err := (Provisioner{}).download(context.Background(), release, archivePath); err != nil {
				t.Fatal(err)
			}
			root := filepath.Join(t.TempDir(), "rootfs")
			if err := os.Mkdir(root, 0700); err != nil {
				t.Fatal(err)
			}
			if _, err := extractArchive(archivePath, root, defaultRootfsLimits); err != nil {
				t.Fatal(err)
			}
		})
	}
}
