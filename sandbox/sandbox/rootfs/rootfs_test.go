//go:build linux

package rootfs

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type archiveEntry struct {
	name string
	kind byte
	mode int64
	body []byte
	link string
}

func makeArchive(t *testing.T, entries ...archiveEntry) []byte {
	t.Helper()
	var output bytes.Buffer
	compressed := gzip.NewWriter(&output)
	tarWriter := tar.NewWriter(compressed)
	for _, entry := range entries {
		header := &tar.Header{
			Name:     entry.name,
			Mode:     entry.mode,
			Size:     int64(len(entry.body)),
			Typeflag: entry.kind,
			Linkname: entry.link,
		}
		if entry.kind == tar.TypeDir || entry.kind == tar.TypeSymlink || entry.kind == tar.TypeLink {
			header.Size = 0
		}
		if err := tarWriter.WriteHeader(header); err != nil {
			t.Fatalf("write tar header %q: %v", entry.name, err)
		}
		if len(entry.body) > 0 {
			if _, err := tarWriter.Write(entry.body); err != nil {
				t.Fatalf("write tar body %q: %v", entry.name, err)
			}
		}
	}
	if err := tarWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := compressed.Close(); err != nil {
		t.Fatal(err)
	}
	return output.Bytes()
}

func minimalArchive(t *testing.T) []byte {
	return makeArchive(t,
		archiveEntry{name: "./", kind: tar.TypeDir, mode: 0755},
		archiveEntry{name: "./bin/", kind: tar.TypeDir, mode: 0755},
		archiveEntry{name: "./etc/", kind: tar.TypeDir, mode: 0755},
		archiveEntry{name: "./proc/", kind: tar.TypeDir, mode: 0555},
		archiveEntry{name: "./bin/busybox", kind: tar.TypeReg, mode: 04755, body: []byte("busybox")},
		archiveEntry{name: "./bin/sh", kind: tar.TypeSymlink, mode: 0777, link: "busybox"},
		archiveEntry{name: "./bin/echo", kind: tar.TypeSymlink, mode: 0777, link: "/bin/busybox"},
		archiveEntry{name: "./etc/alpine-release", kind: tar.TypeReg, mode: 0644, body: []byte("3.24.1\n")},
	)
}

const testReleaseURL = "https://dl-cdn.alpinelinux.org/alpine/v3.24/releases/x86_64/rootfs.tar.gz"

func archiveRelease(t *testing.T, body []byte) ReleaseInfo {
	t.Helper()
	production, ok := releaseCatalog[runtime.GOARCH]
	if !ok {
		t.Fatalf("unsupported test architecture %q", runtime.GOARCH)
	}
	digest := sha256.Sum256(body)
	return ReleaseInfo{
		GoArch:          runtime.GOARCH,
		AlpineArch:      production.AlpineArch,
		ArchiveName:     "synthetic-rootfs.tar.gz",
		URL:             testReleaseURL,
		SHA256:          hex.EncodeToString(digest[:]),
		TreeSHA256:      archiveTreeDigest(t, body),
		MaxArchiveBytes: int64(len(body)),
	}
}

func archiveTreeDigest(t *testing.T, body []byte) string {
	t.Helper()
	archivePath := filepath.Join(t.TempDir(), "archive.tar.gz")
	root := filepath.Join(t.TempDir(), "rootfs")
	if err := os.WriteFile(archivePath, body, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	if err := extractArchive(archivePath, root, defaultExtractionLimits); err != nil {
		t.Fatalf("extract synthetic archive: %v", err)
	}
	digest, err := treeDigest(root)
	if err != nil {
		t.Fatalf("hash synthetic archive: %v", err)
	}
	return digest
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func testResponse(status int, body []byte) *http.Response {
	return &http.Response{
		StatusCode:    status,
		Status:        fmt.Sprintf("%d %s", status, http.StatusText(status)),
		Header:        make(http.Header),
		Body:          io.NopCloser(bytes.NewReader(body)),
		ContentLength: int64(len(body)),
	}
}

func testProvisioner(t *testing.T, body []byte, status int, requests *atomic.Int32) *Provisioner {
	t.Helper()
	release := archiveRelease(t, body)
	transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if requests != nil {
			requests.Add(1)
		}
		if status == http.StatusOK {
			return testResponse(status, body), nil
		}
		return testResponse(status, nil), nil
	})
	return &Provisioner{
		CacheDir: t.TempDir(),
		Client:   &http.Client{Transport: transport, Timeout: 2 * time.Second},
		releases: map[string]ReleaseInfo{runtime.GOARCH: release},
	}
}

func TestReleaseInfoAndCachePath(t *testing.T) {
	tests := []struct {
		goArch     string
		alpineArch string
	}{
		{goArch: "amd64", alpineArch: "x86_64"},
		{goArch: "arm64", alpineArch: "aarch64"},
	}
	for _, tt := range tests {
		t.Run(tt.goArch, func(t *testing.T) {
			release, err := ReleaseInfoFor(tt.goArch)
			if err != nil {
				t.Fatal(err)
			}
			if release.AlpineArch != tt.alpineArch {
				t.Fatalf("AlpineArch = %q, want %q", release.AlpineArch, tt.alpineArch)
			}
			path, err := CachePath("/cache", tt.goArch)
			if err != nil {
				t.Fatal(err)
			}
			want := filepath.Join("/cache", "bcs-zc241t-sandbox", "rootfs", "alpine", "3.24.1", tt.alpineArch)
			if path != want {
				t.Fatalf("CachePath() = %q, want %q", path, want)
			}
		})
	}
	if _, err := ReleaseInfoFor("ppc64le"); err == nil {
		t.Fatal("ReleaseInfoFor() accepted unsupported architecture")
	}
}

func TestExplicitMissingRootfsDoesNotTouchCacheOrNetwork(t *testing.T) {
	cache := t.TempDir()
	source := filepath.Join(t.TempDir(), "missing-rootfs")
	p := Provisioner{CacheDir: cache}
	if _, err := p.Resolve(source); err == nil {
		t.Fatal("Resolve() accepted a missing explicit rootfs")
	}
	entries, err := os.ReadDir(cache)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("explicit rootfs failure modified cache: %v", entries)
	}
}

func TestProvisionAndReuseOffline(t *testing.T) {
	body := minimalArchive(t)
	var requests atomic.Int32
	p := testProvisioner(t, body, http.StatusOK, &requests)
	target, err := p.Resolve("")
	if err != nil {
		t.Fatalf("first Resolve() error = %v", err)
	}
	if requests.Load() != 1 {
		t.Fatalf("request count = %d, want 1", requests.Load())
	}
	if err := validatePublishedRootfs(target, p.releases[runtime.GOARCH]); err != nil {
		t.Fatalf("published rootfs is invalid: %v", err)
	}
	if got, err := p.Resolve(""); err != nil || got != target {
		t.Fatalf("offline Resolve() = %q, %v; want %q, nil", got, err, target)
	}
	if requests.Load() != 1 {
		t.Fatalf("offline reuse made another request: %d", requests.Load())
	}
}

func TestInvalidManifestIsReplaced(t *testing.T) {
	body := minimalArchive(t)
	var requests atomic.Int32
	p := testProvisioner(t, body, http.StatusOK, &requests)
	target, err := p.Resolve("")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, manifestName), []byte("{}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Resolve(""); err != nil {
		t.Fatalf("Resolve() did not repair invalid manifest: %v", err)
	}
	if requests.Load() != 2 {
		t.Fatalf("request count = %d, want 2", requests.Load())
	}
}

func TestProvisioningFailuresLeaveNoPublishedRootfs(t *testing.T) {
	body := minimalArchive(t)
	var requests atomic.Int32
	p := testProvisioner(t, body, http.StatusOK, &requests)
	release := p.releases[runtime.GOARCH]
	release.SHA256 = strings.Repeat("0", 64)
	p.releases[runtime.GOARCH] = release
	if _, err := p.Resolve(""); err == nil || !strings.Contains(err.Error(), "configure rootfs_source") {
		t.Fatalf("digest failure = %v, want actionable cache/custom-rootfs error", err)
	}
	target, _ := CachePath(p.CacheDir, runtime.GOARCH)
	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Fatalf("failed provisioning left published rootfs: %v", err)
	}
	if temporary, _ := filepath.Glob(filepath.Join(filepath.Dir(target), ".rootfs-*")); len(temporary) != 0 {
		t.Fatalf("failed provisioning left temporary directories: %v", temporary)
	}
}

func TestProvisioningFailureAndResponseLimits(t *testing.T) {
	body := minimalArchive(t)
	for _, tt := range []struct {
		name      string
		status    int
		maxBytes  int64
		badDigest bool
		want      string
	}{
		{name: "http failure", status: http.StatusNotFound, want: "404"},
		{name: "response too large", status: http.StatusOK, maxBytes: int64(len(body) - 1), want: "archive limit"},
		{name: "digest mismatch", status: http.StatusOK, badDigest: true, want: "SHA-256 mismatch"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			p := testProvisioner(t, body, tt.status, nil)
			release := p.releases[runtime.GOARCH]
			if tt.maxBytes != 0 {
				release.MaxArchiveBytes = tt.maxBytes
			}
			if tt.badDigest {
				release.SHA256 = strings.Repeat("f", 64)
			}
			p.releases[runtime.GOARCH] = release
			if _, err := p.Resolve(""); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Resolve() error = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestConcurrentProvisioningDownloadsOnce(t *testing.T) {
	body := minimalArchive(t)
	var requests atomic.Int32
	p := testProvisioner(t, body, http.StatusOK, &requests)
	var wait sync.WaitGroup
	errors := make(chan error, 2)
	for range 2 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			_, err := p.Resolve("")
			errors <- err
		}()
	}
	wait.Wait()
	close(errors)
	for err := range errors {
		if err != nil {
			t.Fatal(err)
		}
	}
	if requests.Load() != 1 {
		t.Fatalf("request count = %d, want exactly 1", requests.Load())
	}
}

func TestAtomicRenameFailureCleansTemporaryRootfs(t *testing.T) {
	body := minimalArchive(t)
	p := testProvisioner(t, body, http.StatusOK, nil)
	p.renamePath = func(string, string) error { return errors.New("rename denied") }
	if _, err := p.Resolve(""); err == nil || !strings.Contains(err.Error(), "atomically publish") {
		t.Fatalf("rename failure = %v", err)
	}
	target, _ := CachePath(p.CacheDir, runtime.GOARCH)
	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Fatalf("rename failure left target: %v", err)
	}
	if temporary, _ := filepath.Glob(filepath.Join(filepath.Dir(target), ".rootfs-*")); len(temporary) != 0 {
		t.Fatalf("rename failure left temporary directories: %v", temporary)
	}
}

func TestHTTPSRedirectIsRequired(t *testing.T) {
	body := minimalArchive(t)
	p := testProvisioner(t, body, http.StatusOK, nil)
	p.Client = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		response := testResponse(http.StatusFound, nil)
		response.Header.Set("Location", "http://dl-cdn.alpinelinux.org/rootfs.tar.gz")
		return response, nil
	})}
	if _, err := p.Resolve(""); err == nil || !strings.Contains(err.Error(), "non-HTTPS") {
		t.Fatalf("HTTP redirect error = %v, want HTTPS rejection", err)
	}
}

func TestHTTPSRedirectAllowsSameHostAndRejectsHostChanges(t *testing.T) {
	body := minimalArchive(t)
	p := testProvisioner(t, body, http.StatusOK, nil)
	var requests atomic.Int32
	p.Client.Transport = roundTripFunc(func(request *http.Request) (*http.Response, error) {
		requests.Add(1)
		if request.URL.String() == testReleaseURL {
			response := testResponse(http.StatusFound, nil)
			response.Header.Set("Location", testReleaseURL+".final")
			return response, nil
		}
		return testResponse(http.StatusOK, body), nil
	})
	if _, err := p.Resolve(""); err != nil {
		t.Fatalf("same-host HTTPS redirect failed: %v", err)
	}
	if requests.Load() != 2 {
		t.Fatalf("same-host redirect requests = %d, want 2", requests.Load())
	}

	p = testProvisioner(t, body, http.StatusOK, nil)
	p.Client = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		response := testResponse(http.StatusFound, nil)
		response.Header.Set("Location", "https://other.example.invalid/rootfs.tar.gz")
		return response, nil
	})}
	if _, err := p.Resolve(""); err == nil || !strings.Contains(err.Error(), "different host") {
		t.Fatalf("different-host HTTPS redirect error = %v", err)
	}
}

func TestDownloadTimeout(t *testing.T) {
	body := minimalArchive(t)
	p := testProvisioner(t, body, http.StatusOK, nil)
	p.Client.Transport = roundTripFunc(func(request *http.Request) (*http.Response, error) {
		<-request.Context().Done()
		return nil, request.Context().Err()
	})
	p.Client.Timeout = 10 * time.Millisecond
	if _, err := p.Resolve(""); err == nil || !strings.Contains(err.Error(), "request failed") {
		t.Fatalf("timeout error = %v, want request failure", err)
	}
}

func TestSecureExtraction(t *testing.T) {
	tests := []struct {
		name    string
		entries []archiveEntry
		limits  extractionLimits
		want    string
	}{
		{name: "absolute path", entries: []archiveEntry{{name: "/etc/passwd", kind: tar.TypeReg, mode: 0644, body: []byte("x")}}, want: "absolute"},
		{name: "parent traversal", entries: []archiveEntry{{name: "../escape", kind: tar.TypeReg, mode: 0644, body: []byte("x")}}, want: "safe relative"},
		{name: "escaping symlink", entries: []archiveEntry{{name: "etc/link", kind: tar.TypeSymlink, mode: 0777, link: "../../outside"}}, want: "escapes"},
		{name: "symlink parent", entries: []archiveEntry{{name: "bin", kind: tar.TypeSymlink, mode: 0777, link: "."}, {name: "bin/file", kind: tar.TypeReg, mode: 0644, body: []byte("x")}}, want: "non-directory"},
		{name: "duplicate", entries: []archiveEntry{{name: "file", kind: tar.TypeReg, mode: 0644, body: []byte("a")}, {name: "file", kind: tar.TypeReg, mode: 0644, body: []byte("b")}}, want: "duplicate"},
		{name: "hard link outside", entries: []archiveEntry{{name: "link", kind: tar.TypeLink, mode: 0644, link: "../outside"}}, want: "invalid target"},
		{name: "device node", entries: []archiveEntry{{name: "dev/null", kind: tar.TypeChar, mode: 0600}}, want: "unsupported type"},
		{name: "file too large", entries: []archiveEntry{{name: "file", kind: tar.TypeReg, mode: 0644, body: []byte("123")}}, limits: extractionLimits{MaxCompressedBytes: 1 << 20, MaxExtractedBytes: 1 << 20, MaxFileBytes: 2, MaxEntries: 10}, want: "file limit"},
		{name: "too many entries", entries: []archiveEntry{{name: "one", kind: tar.TypeReg, mode: 0644, body: []byte("1")}, {name: "two", kind: tar.TypeReg, mode: 0644, body: []byte("2")}}, limits: extractionLimits{MaxCompressedBytes: 1 << 20, MaxExtractedBytes: 1 << 20, MaxFileBytes: 10, MaxEntries: 1}, want: "entry limit"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			archive := makeArchive(t, tt.entries...)
			archivePath := filepath.Join(t.TempDir(), "archive.tar.gz")
			if err := os.WriteFile(archivePath, archive, 0600); err != nil {
				t.Fatal(err)
			}
			limits := tt.limits
			if limits.MaxCompressedBytes == 0 {
				limits = defaultExtractionLimits
			}
			destination := filepath.Join(t.TempDir(), "rootfs")
			if err := os.Mkdir(destination, 0700); err != nil {
				t.Fatal(err)
			}
			err := extractArchive(archivePath, destination, limits)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("extractArchive() error = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestNormalizeArchivePathAcceptsRootMarkersOnlyAtTheRoot(t *testing.T) {
	tests := []struct {
		name       string
		want       string
		rootMarker bool
		wantErr    bool
	}{
		{name: ".", rootMarker: true},
		{name: "./", rootMarker: true},
		{name: "./bin/", want: "bin"},
		{name: "././bin/busybox", want: "bin/busybox"},
		{name: "./../escape", wantErr: true},
		{name: "./../../etc", wantErr: true},
		{name: ".//etc", wantErr: true},
		{name: "bin/../etc", wantErr: true},
		{name: "/etc", wantErr: true},
		{name: "././", wantErr: true},
		{name: "bin//etc", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, rootMarker, err := normalizeArchivePath(tt.name)
			if (err != nil) != tt.wantErr {
				t.Fatalf("normalizeArchivePath() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err == nil && (got != tt.want || rootMarker != tt.rootMarker) {
				t.Fatalf("normalizeArchivePath() = %q, %v; want %q, %v", got, rootMarker, tt.want, tt.rootMarker)
			}
		})
	}
}

func TestExtractionRejectsRootMarkerWithTheWrongType(t *testing.T) {
	archive := makeArchive(t, archiveEntry{name: ".", kind: tar.TypeReg, mode: 0644})
	archivePath := filepath.Join(t.TempDir(), "archive.tar.gz")
	root := filepath.Join(t.TempDir(), "rootfs")
	if err := os.WriteFile(archivePath, archive, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	if err := extractArchive(archivePath, root, defaultExtractionLimits); err == nil || !strings.Contains(err.Error(), "root marker") {
		t.Fatalf("extractArchive() error = %v, want root-marker error", err)
	}
}

func TestSecureExtractionAllowsInternalLinksAndStripsSpecialBits(t *testing.T) {
	archive := minimalArchive(t)
	archivePath := filepath.Join(t.TempDir(), "archive.tar.gz")
	if err := os.WriteFile(archivePath, archive, 0600); err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(t.TempDir(), "rootfs")
	if err := os.Mkdir(destination, 0700); err != nil {
		t.Fatal(err)
	}
	if err := extractArchive(archivePath, destination, defaultExtractionLimits); err != nil {
		t.Fatalf("extractArchive() error = %v", err)
	}
	if err := validateRootfsLayout(destination); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(destination, "bin", "busybox"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&os.ModeSetuid != 0 || info.Mode().Perm() != 0755 {
		t.Fatalf("busybox mode = %v, want 0755 without setuid", info.Mode())
	}
}

func TestCorruptArchiveIsRejected(t *testing.T) {
	archivePath := filepath.Join(t.TempDir(), "archive.tar.gz")
	if err := os.WriteFile(archivePath, []byte("not gzip"), 0600); err != nil {
		t.Fatal(err)
	}
	err := extractArchive(archivePath, filepath.Join(t.TempDir(), "rootfs"), defaultExtractionLimits)
	if err == nil || !strings.Contains(err.Error(), "gzip") {
		t.Fatalf("extractArchive() error = %v, want gzip error", err)
	}
}

func TestManifestValidationRejectsUnexpectedFields(t *testing.T) {
	body := minimalArchive(t)
	p := testProvisioner(t, body, http.StatusOK, nil)
	target, err := p.Resolve("")
	if err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(target, manifestName)
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	data = bytes.TrimSpace(data)
	data = append(data[:len(data)-1], []byte(`,"unexpected":true}`)...)
	if err := os.WriteFile(manifestPath, data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := validatePublishedRootfs(target, p.releases[runtime.GOARCH]); err == nil {
		t.Fatal("validatePublishedRootfs() accepted unexpected manifest field")
	}
}

func TestModifiedCachedTreeIsRejectedAndPreservedOffline(t *testing.T) {
	tests := []struct {
		name   string
		modify func(t *testing.T, target string)
	}{
		{name: "file contents", modify: func(t *testing.T, target string) {
			if err := os.WriteFile(filepath.Join(target, "bin", "busybox"), []byte("modified"), 0755); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "file mode", modify: func(t *testing.T, target string) {
			if err := os.Chmod(filepath.Join(target, "bin", "busybox"), 0700); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "symlink target", modify: func(t *testing.T, target string) {
			name := filepath.Join(target, "bin", "sh")
			if err := os.Remove(name); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("echo", name); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "added file", modify: func(t *testing.T, target string) {
			if err := os.WriteFile(filepath.Join(target, "bin", "added"), []byte("added"), 0644); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "removed file", modify: func(t *testing.T, target string) {
			if err := os.Remove(filepath.Join(target, "bin", "echo")); err != nil {
				t.Fatal(err)
			}
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body := minimalArchive(t)
			p := testProvisioner(t, body, http.StatusOK, nil)
			target, err := p.Resolve("")
			if err != nil {
				t.Fatal(err)
			}
			tt.modify(t, target)
			if err := validatePublishedRootfs(target, p.releases[runtime.GOARCH]); err == nil {
				t.Fatal("validatePublishedRootfs() accepted a modified tree")
			}
			p.Client.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
				return nil, errors.New("offline")
			})
			if _, err := p.Resolve(""); err == nil {
				t.Fatal("offline Resolve() accepted a modified tree")
			}
			if _, err := os.Lstat(target); err != nil {
				t.Fatalf("offline repair removed the invalid fallback: %v", err)
			}
		})
	}
}

func TestReplacementFailureRestoresPreviousRootfs(t *testing.T) {
	body := minimalArchive(t)
	p := testProvisioner(t, body, http.StatusOK, nil)
	target, err := p.Resolve("")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, manifestName), []byte("{}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	p.renamePath = func(old, new string) error {
		if strings.HasSuffix(old, string(os.PathSeparator)+"rootfs") {
			return errors.New("replacement interrupted")
		}
		return os.Rename(old, new)
	}
	if _, err := p.Resolve(""); err == nil || !strings.Contains(err.Error(), "replacement interrupted") {
		t.Fatalf("Resolve() error = %v, want replacement failure", err)
	}
	if data, err := os.ReadFile(filepath.Join(target, manifestName)); err != nil || string(data) != "{}\n" {
		t.Fatalf("previous rootfs was not restored: err=%v data=%q", err, data)
	}
	if backups, _ := filepath.Glob(filepath.Join(filepath.Dir(target), ".rootfs-backup-*")); len(backups) != 0 {
		t.Fatalf("replacement left backups: %v", backups)
	}
}

func TestCacheSymlinksAndUnsafeModesFailClosed(t *testing.T) {
	t.Run("cache root symlink", func(t *testing.T) {
		cache := t.TempDir()
		if err := os.Symlink(t.TempDir(), filepath.Join(cache, "bcs-zc241t-sandbox")); err != nil {
			t.Fatal(err)
		}
		p := Provisioner{CacheDir: cache}
		if _, err := p.Resolve(""); err == nil {
			t.Fatal("Resolve() followed a cache-root symlink")
		}
	})

	t.Run("lock symlink", func(t *testing.T) {
		cache := t.TempDir()
		version := filepath.Join(cache, "bcs-zc241t-sandbox", "rootfs", Provider, Version)
		if err := os.MkdirAll(version, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(filepath.Join(t.TempDir(), "lock"), filepath.Join(version, lockName)); err != nil {
			t.Fatal(err)
		}
		p := Provisioner{CacheDir: cache}
		if _, err := p.Resolve(""); err == nil {
			t.Fatal("Resolve() followed a lock symlink")
		}
	})

	t.Run("target mode", func(t *testing.T) {
		body := minimalArchive(t)
		p := testProvisioner(t, body, http.StatusOK, nil)
		target, err := p.Resolve("")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(target, 0775); err != nil {
			t.Fatal(err)
		}
		p.Client.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
			return nil, errors.New("offline")
		})
		if _, err := p.Resolve(""); err == nil {
			t.Fatal("Resolve() accepted group/other-writable target")
		}
		if _, err := os.Lstat(target); err != nil {
			t.Fatalf("unsafe target was removed: %v", err)
		}
	})

	t.Run("target symlink", func(t *testing.T) {
		body := minimalArchive(t)
		p := testProvisioner(t, body, http.StatusOK, nil)
		target, err := p.Resolve("")
		if err != nil {
			t.Fatal(err)
		}
		external := t.TempDir()
		marker := filepath.Join(external, "marker")
		if err := os.WriteFile(marker, []byte("unchanged"), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.RemoveAll(target); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(external, target); err != nil {
			t.Fatal(err)
		}
		p.Client.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
			return nil, errors.New("offline")
		})
		if _, err := p.Resolve(""); err == nil {
			t.Fatal("Resolve() followed a target symlink")
		}
		if got, err := os.ReadFile(marker); err != nil || string(got) != "unchanged" {
			t.Fatalf("target symlink escaped into external data: err=%v data=%q", err, got)
		}
		if info, err := os.Lstat(target); err != nil || info.Mode()&os.ModeSymlink == 0 {
			t.Fatalf("target symlink was removed or followed: err=%v info=%v", err, info)
		}
	})

	t.Run("manifest symlink", func(t *testing.T) {
		body := minimalArchive(t)
		p := testProvisioner(t, body, http.StatusOK, nil)
		target, err := p.Resolve("")
		if err != nil {
			t.Fatal(err)
		}
		external := filepath.Join(t.TempDir(), "manifest")
		if err := os.WriteFile(external, []byte("external"), 0600); err != nil {
			t.Fatal(err)
		}
		manifestPath := filepath.Join(target, manifestName)
		if err := os.Remove(manifestPath); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(external, manifestPath); err != nil {
			t.Fatal(err)
		}
		p.Client.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
			return nil, errors.New("offline")
		})
		if _, err := p.Resolve(""); err == nil {
			t.Fatal("Resolve() followed a manifest symlink")
		}
		if got, err := os.ReadFile(external); err != nil || string(got) != "external" {
			t.Fatalf("manifest symlink escaped into external data: err=%v data=%q", err, got)
		}
	})
}

func TestReleaseMetadataIsPinned(t *testing.T) {
	release, err := ReleaseInfoFor("amd64")
	if err != nil {
		t.Fatal(err)
	}
	if release.URL != "https://dl-cdn.alpinelinux.org/alpine/v3.24/releases/x86_64/alpine-minirootfs-3.24.1-x86_64.tar.gz" {
		t.Fatalf("unexpected release URL %q", release.URL)
	}
	if release.MaxArchiveBytes != 3698422 || release.SHA256 != "41f73e3cf5fa919b8aa5ca6b30dc48f0da2720776d7423e2a7748211456fe081" || release.TreeSHA256 != "f35a4d7394df512b1727eebe935f54cc38a4b15154e56ad74722cb3683c4eb9f" {
		t.Fatalf("unexpected amd64 release metadata: %+v", release)
	}
}

func TestReleaseURLValidation(t *testing.T) {
	valid := "https://dl-cdn.alpinelinux.org/alpine/v3.24/releases/x86_64/rootfs.tar.gz"
	if _, err := validateReleaseURL(valid, false); err != nil {
		t.Fatalf("valid release URL rejected: %v", err)
	}
	for _, raw := range []string{
		"http://dl-cdn.alpinelinux.org/rootfs.tar.gz",
		"https://mirror.example/rootfs.tar.gz",
		"https://user:pass@dl-cdn.alpinelinux.org/rootfs.tar.gz",
		"https://dl-cdn.alpinelinux.org/rootfs.tar.gz?redirect=1",
		"https://dl-cdn.alpinelinux.org/alpine/../rootfs.tar.gz",
	} {
		if _, err := validateReleaseURL(raw, false); err == nil {
			t.Errorf("validateReleaseURL(%q) accepted malformed or untrusted URL", raw)
		}
	}
}

func TestHTTPErrorIncludesStatus(t *testing.T) {
	p := testProvisioner(t, minimalArchive(t), http.StatusServiceUnavailable, nil)
	if _, err := p.Resolve(""); err == nil || !strings.Contains(err.Error(), "503") {
		t.Fatalf("HTTP error = %v, want status", err)
	}
}

func TestExplicitRootfsDirectoryIsReturnedUnchanged(t *testing.T) {
	source := t.TempDir()
	p := Provisioner{CacheDir: filepath.Join(t.TempDir(), "cache")}
	got, err := p.Resolve(source)
	if err != nil {
		t.Fatal(err)
	}
	if got != source {
		t.Fatalf("Resolve() = %q, want %q", got, source)
	}
}
