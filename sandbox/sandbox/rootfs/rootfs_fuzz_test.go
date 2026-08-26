//go:build linux

package rootfs

import "testing"

func FuzzNormalizeArchivePathNeverPanics(f *testing.F) {
	f.Add("./bin/sh")
	f.Add("../escape")
	f.Add("bin/../etc")
	f.Add("./")
	f.Fuzz(func(t *testing.T, name string) {
		_, _, _ = normalizeArchivePath(name)
	})
}

func FuzzValidateInternalTargetNeverPanics(f *testing.F) {
	f.Add("bin/link", "../etc")
	f.Add("lib/ld-musl", "../lib/ld-musl")
	f.Fuzz(func(t *testing.T, name, target string) {
		_ = validateInternalTarget(name, target)
	})
}
