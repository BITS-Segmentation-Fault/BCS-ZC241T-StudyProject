//go:build linux

package rootfs

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mholt/archives"
	"golang.org/x/sys/unix"
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
	tarBytes := makeTarArchive(t, entries...)
	var output bytes.Buffer
	compressed := gzip.NewWriter(&output)
	if _, err := compressed.Write(tarBytes); err != nil {
		t.Fatal(err)
	}
	if err := compressed.Close(); err != nil {
		t.Fatal(err)
	}
	return output.Bytes()
}

func makeTarArchive(t *testing.T, entries ...archiveEntry) []byte {
	t.Helper()
	var output bytes.Buffer
	tarWriter := tar.NewWriter(&output)
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
	return output.Bytes()
}

func makeZstdArchive(t *testing.T, tarBytes []byte) []byte {
	t.Helper()
	var output bytes.Buffer
	compressed, err := (archives.Zstd{}).OpenWriter(&output)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := compressed.Write(tarBytes); err != nil {
		t.Fatal(err)
	}
	if err := compressed.Close(); err != nil {
		t.Fatal(err)
	}
	return output.Bytes()
}

func makeZipArchive(t *testing.T, entries ...archiveEntry) []byte {
	t.Helper()
	var output bytes.Buffer
	writer := zip.NewWriter(&output)
	for _, entry := range entries {
		name := strings.TrimPrefix(entry.name, "./")
		if name == "" {
			continue
		}
		if entry.kind == tar.TypeDir && !strings.HasSuffix(name, "/") {
			name += "/"
		}
		header := &zip.FileHeader{Name: name, Method: zip.Deflate}
		header.SetMode(fs.FileMode(entry.mode))
		file, err := writer.CreateHeader(header)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := file.Write(entry.body); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
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
	)
}

func restrictiveArchive(t *testing.T) []byte {
	return makeArchive(t,
		archiveEntry{name: "./", kind: tar.TypeDir, mode: 0755},
		archiveEntry{name: "./var/", kind: tar.TypeDir, mode: 0755},
		archiveEntry{name: "./var/lib/", kind: tar.TypeDir, mode: 0755},
		archiveEntry{name: "./var/lib/snapd/", kind: tar.TypeDir, mode: 0755},
		archiveEntry{name: "./var/lib/snapd/void/", kind: tar.TypeDir, mode: 0111},
		archiveEntry{name: "./var/lib/snapd/void/state", kind: tar.TypeReg, mode: 0000, body: []byte("unchanged")},
	)
}

func restrictiveNestedDirectoriesArchive(t *testing.T) []byte {
	return makeArchive(t,
		archiveEntry{name: "./", kind: tar.TypeDir, mode: 0755},
		archiveEntry{name: "./private/", kind: tar.TypeDir, mode: 0000},
		archiveEntry{name: "./private/nested/", kind: tar.TypeDir, mode: 0000},
	)
}

const testReleaseURL = "https://dl-cdn.alpinelinux.org/alpine/v3.24/releases/x86_64/rootfs.tar.gz"

func archiveRelease(t *testing.T, body []byte) managedRelease {
	t.Helper()
	production, ok := defaultManagedSource.Releases[runtime.GOARCH]
	if !ok {
		t.Fatalf("unsupported test architecture %q", runtime.GOARCH)
	}
	digest := sha256.Sum256(body)
	return managedRelease{
		Architecture:  production.Architecture,
		CacheKey:      production.CacheKey,
		ArchiveName:   "synthetic-rootfs.tar.gz",
		URL:           testReleaseURL,
		ArchiveSHA256: hex.EncodeToString(digest[:]),
	}
}

func extractArchiveForTest(archivePath, destination string, limits rootfsLimits) error {
	_, err := extractArchive(archivePath, destination, limits)
	return err
}

func validatePublishedRootfsForTest(root string, source managedSource, release managedRelease) error {
	return validatePublishedRootfs(root, source, release, defaultRootfsLimits)
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
	source := managedSource{
		Provider: "test-provider",
		Version:  "test-version",
		Releases: map[string]managedRelease{runtime.GOARCH: release},
	}
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
		source:   &source,
	}
}

func testRemoteSource(t *testing.T, body []byte) RemoteSource {
	t.Helper()
	digest := sha256.Sum256(body)
	return RemoteSource{
		URL:           "https://mirror.example/rootfs.tar.gz",
		Architecture:  runtime.GOARCH,
		ArchiveSHA256: hex.EncodeToString(digest[:]),
	}
}

func testRemoteProvisioner(t *testing.T, body []byte, remote RemoteSource, requests *atomic.Int32) *Provisioner {
	t.Helper()
	transport := roundTripFunc(func(*http.Request) (*http.Response, error) {
		if requests != nil {
			requests.Add(1)
		}
		return testResponse(http.StatusOK, body), nil
	})
	return &Provisioner{
		CacheDir: t.TempDir(),
		Client:   &http.Client{Transport: transport, Timeout: 2 * time.Second},
	}
}

func remoteCachePath(t *testing.T, p *Provisioner, remote RemoteSource) string {
	t.Helper()
	source := managedSource{Provider: "remote", Version: "v1"}
	release := managedRelease{
		Architecture:  remote.Architecture,
		CacheKey:      remote.ArchiveSHA256,
		ArchiveName:   "rootfs.tar.gz",
		URL:           remote.URL,
		ArchiveSHA256: remote.ArchiveSHA256,
	}
	target, err := cachePath(p.CacheDir, source, release)
	if err != nil {
		t.Fatal(err)
	}
	return target
}

func testCachePath(t *testing.T, p *Provisioner) string {
	t.Helper()
	source := p.sourceForProvisioning()
	release := source.Releases[runtime.GOARCH]
	target, err := cachePath(p.CacheDir, source, release)
	if err != nil {
		t.Fatal(err)
	}
	return target
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
	if err := validatePublishedRootfsForTest(target, p.sourceForProvisioning(), p.sourceForProvisioning().Releases[runtime.GOARCH]); err != nil {
		t.Fatalf("published rootfs is invalid: %v", err)
	}
	if got, err := p.Resolve(""); err != nil || got != target {
		t.Fatalf("offline Resolve() = %q, %v; want %q, nil", got, err, target)
	}
	if requests.Load() != 1 {
		t.Fatalf("offline reuse made another request: %d", requests.Load())
	}
}

func TestRestrictiveRootfsPermissionsSurviveProvisionAndReuse(t *testing.T) {
	body := restrictiveArchive(t)
	var requests atomic.Int32
	p := testProvisioner(t, body, http.StatusOK, &requests)
	target, err := p.Resolve("")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = os.Chmod(filepath.Join(target, "var/lib/snapd/void"), 0700)
	})
	checkModes := func() {
		t.Helper()
		void, err := os.Stat(filepath.Join(target, "var/lib/snapd/void"))
		if err != nil {
			t.Fatal(err)
		}
		if void.Mode().Perm() != 0111 {
			t.Fatalf("void mode = %#o, want 0111", void.Mode().Perm())
		}
		state, err := os.Stat(filepath.Join(target, "var/lib/snapd/void/state"))
		if err != nil {
			t.Fatal(err)
		}
		if state.Mode().Perm() != 0000 {
			t.Fatalf("state mode = %#o, want 0000", state.Mode().Perm())
		}
	}
	checkModes()
	p.Client.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("offline")
	})
	if got, err := p.Resolve(""); err != nil || got != target {
		t.Fatalf("offline reuse = %q, %v; want %q, nil", got, err, target)
	}
	if requests.Load() != 1 {
		t.Fatalf("offline reuse made %d requests, want 1", requests.Load())
	}
	checkModes()
}

func TestRestrictiveDirectoryModesApplyDeepestFirst(t *testing.T) {
	archivePath := filepath.Join(t.TempDir(), "archive.tar.gz")
	if err := os.WriteFile(archivePath, restrictiveNestedDirectoriesArchive(t), 0600); err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(t.TempDir(), "rootfs")
	if err := os.Mkdir(destination, 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := extractArchive(archivePath, destination, defaultRootfsLimits); err != nil {
		t.Fatalf("extractArchive() error = %v", err)
	}
	private := filepath.Join(destination, "private")
	nested := filepath.Join(private, "nested")
	privateInfo, err := os.Lstat(private)
	if err != nil {
		t.Fatal(err)
	}
	if privateInfo.Mode().Perm() != 0000 {
		t.Fatalf("private mode = %#o, want 0000", privateInfo.Mode().Perm())
	}
	if err := os.Chmod(private, 0700); err != nil {
		t.Fatal(err)
	}
	nestedInfo, err := os.Lstat(nested)
	if err != nil {
		t.Fatal(err)
	}
	if nestedInfo.Mode().Perm() != 0000 {
		t.Fatalf("nested mode = %#o, want 0000", nestedInfo.Mode().Perm())
	}
	if err := os.Chmod(nested, 0700); err != nil {
		t.Fatal(err)
	}
}

func TestRemoteRootfsProvisionAndOfflineReuse(t *testing.T) {
	body := minimalArchive(t)
	remote := testRemoteSource(t, body)
	var requests atomic.Int32
	p := testRemoteProvisioner(t, body, remote, &requests)
	target, err := p.ResolveRemote(remote)
	if err != nil {
		t.Fatalf("first ResolveRemote() error = %v", err)
	}
	if strings.Contains(target, remote.URL) || filepath.Base(target) != remote.ArchiveSHA256 {
		t.Fatalf("remote cache path = %q, want only the archive digest as its key", target)
	}
	if requests.Load() != 1 {
		t.Fatalf("request count = %d, want 1", requests.Load())
	}
	data, err := os.ReadFile(filepath.Join(target, manifestName))
	if err != nil {
		t.Fatal(err)
	}
	var got manifest
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	if got.Provider != "remote" || got.Version != "v1" || got.SHA256 != remote.ArchiveSHA256 {
		t.Fatalf("remote manifest = %+v, want verified remote metadata", got)
	}

	offline := remote
	offline.URL = "https://another.example/rootfs.tar.gz"
	p.Client.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
		requests.Add(1)
		return nil, errors.New("offline")
	})
	gotTarget, err := p.ResolveRemote(offline)
	if err != nil || gotTarget != target {
		t.Fatalf("offline ResolveRemote() = %q, %v; want %q, nil", gotTarget, err, target)
	}
	if requests.Load() != 1 {
		t.Fatalf("same archive digest made another request: %d", requests.Load())
	}
}

func TestRemoteRootfsReuseRevalidatesRecordedLimits(t *testing.T) {
	body := makeArchive(t, archiveEntry{
		name: "payload", kind: tar.TypeReg, mode: 0600, body: bytes.Repeat([]byte("x"), 2<<20),
	})
	remote := testRemoteSource(t, body)
	remote.MaxExtractedSizeMB = 4
	remote.MaxFileSizeMB = 4
	remote.MaxEntries = 10
	var requests atomic.Int32
	p := testRemoteProvisioner(t, body, remote, &requests)
	target, err := p.ResolveRemote(remote)
	if err != nil {
		t.Fatalf("provision with loose limits = %v", err)
	}

	p.Client.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
		requests.Add(1)
		return nil, errors.New("offline")
	})
	within := remote
	within.MaxExtractedSizeMB = 3
	within.MaxFileSizeMB = 3
	if got, err := p.ResolveRemote(within); err != nil || got != target {
		t.Fatalf("reuse with fitting recorded statistics = %q, %v; want %q, nil", got, err, target)
	}
	if requests.Load() != 1 {
		t.Fatalf("fitting cached statistics made %d requests, want 1", requests.Load())
	}

	tooSmall := within
	tooSmall.MaxExtractedSizeMB = 1
	tooSmall.MaxFileSizeMB = 1
	if _, err := p.ResolveRemote(tooSmall); err == nil || !strings.Contains(err.Error(), "offline") {
		t.Fatalf("reuse with excessive recorded statistics = %v, want offline reprovision failure", err)
	}
	if requests.Load() != 2 {
		t.Fatalf("excessive cached statistics made %d requests, want 2", requests.Load())
	}
	if _, err := os.Stat(target); err != nil {
		t.Fatalf("existing cache was not preserved after failed reprovision: %v", err)
	}
}

func TestRemoteRootfsRejectsInvalidMetadataBeforeCacheOrNetwork(t *testing.T) {
	body := minimalArchive(t)
	digest := sha256.Sum256(body)
	valid := RemoteSource{
		URL:           "https://mirror.example/rootfs.tar.gz",
		Architecture:  runtime.GOARCH,
		ArchiveSHA256: hex.EncodeToString(digest[:]),
	}
	for _, tt := range []struct {
		name   string
		update func(*RemoteSource)
	}{
		{name: "architecture", update: func(remote *RemoteSource) { remote.Architecture = "other" }},
		{name: "url", update: func(remote *RemoteSource) { remote.URL = "http://mirror.example/rootfs.tar.gz" }},
		{name: "uppercase digest", update: func(remote *RemoteSource) { remote.ArchiveSHA256 = strings.ToUpper(remote.ArchiveSHA256) }},
		{name: "short digest", update: func(remote *RemoteSource) { remote.ArchiveSHA256 = remote.ArchiveSHA256[:63] }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			remote := valid
			tt.update(&remote)
			var requests atomic.Int32
			p := testRemoteProvisioner(t, body, valid, &requests)
			if _, err := p.ResolveRemote(remote); err == nil {
				t.Fatal("ResolveRemote() accepted invalid metadata")
			}
			if requests.Load() != 0 {
				t.Fatalf("invalid metadata made %d network requests", requests.Load())
			}
			entries, err := os.ReadDir(p.CacheDir)
			if err != nil {
				t.Fatal(err)
			}
			if len(entries) != 0 {
				t.Fatalf("invalid metadata modified cache: %v", entries)
			}
		})
	}
}

func TestRemoteRootfsRejectsArchiveMismatch(t *testing.T) {
	body := minimalArchive(t)
	remote := testRemoteSource(t, body)
	remote.ArchiveSHA256 = strings.Repeat("0", 64)
	p := testRemoteProvisioner(t, body, remote, nil)
	if _, err := p.ResolveRemote(remote); err == nil || !strings.Contains(err.Error(), "SHA-256 mismatch") {
		t.Fatalf("archive mismatch error = %v", err)
	}
	if _, err := os.Stat(remoteCachePath(t, p, remote)); !os.IsNotExist(err) {
		t.Fatalf("archive mismatch left published cache: %v", err)
	}

}

func TestSelectedManagedSourceControlsCacheAndManifest(t *testing.T) {
	body := minimalArchive(t)
	p := testProvisioner(t, body, http.StatusOK, nil)
	source := p.sourceForProvisioning()
	release := source.Releases[runtime.GOARCH]
	target, err := p.Resolve("")
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(p.CacheDir, "bcs-zc241t-sandbox", "rootfs", "test-provider", "test-version", release.CacheKey)
	if target != want {
		t.Fatalf("managed cache path = %q, want %q", target, want)
	}
	data, err := os.ReadFile(filepath.Join(target, manifestName))
	if err != nil {
		t.Fatal(err)
	}
	var got manifest
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	if got.SchemaVersion != manifestSchemaVersion || got.Provider != source.Provider || got.Version != source.Version ||
		got.Architecture != release.Architecture || got.Archive != release.ArchiveName || got.SHA256 != release.ArchiveSHA256 ||
		got.ExtractedBytes == 0 || got.LargestFileBytes == 0 || got.Entries == 0 {
		t.Fatalf("manifest = %#v, want current archive identity and statistics", got)
	}
}

func TestInvalidManagedMetadataDoesNotTouchCacheOrNetwork(t *testing.T) {
	body := minimalArchive(t)
	for _, tt := range []struct {
		name   string
		update func(*managedSource, *managedRelease)
	}{
		{name: "empty provider", update: func(source *managedSource, _ *managedRelease) { source.Provider = "" }},
		{name: "traversal version", update: func(source *managedSource, _ *managedRelease) { source.Version = "../version" }},
		{name: "empty architecture", update: func(_ *managedSource, release *managedRelease) { release.Architecture = "" }},
		{name: "empty cache key", update: func(_ *managedSource, release *managedRelease) { release.CacheKey = "" }},
		{name: "traversal archive name", update: func(_ *managedSource, release *managedRelease) { release.ArchiveName = "../archive" }},
		{name: "invalid archive digest", update: func(_ *managedSource, release *managedRelease) { release.ArchiveSHA256 = strings.Repeat("0", 63) }},
		{name: "invalid URL", update: func(_ *managedSource, release *managedRelease) { release.URL = "http://example.test/rootfs.tar.gz" }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var requests atomic.Int32
			p := testProvisioner(t, body, http.StatusOK, &requests)
			source := p.sourceForProvisioning()
			release := source.Releases[runtime.GOARCH]
			tt.update(&source, &release)
			source.Releases[runtime.GOARCH] = release
			p.source = &source
			if _, err := p.Resolve(""); err == nil {
				t.Fatal("Resolve() accepted invalid managed metadata")
			}
			if requests.Load() != 0 {
				t.Fatalf("metadata validation made %d network requests", requests.Load())
			}
			entries, err := os.ReadDir(p.CacheDir)
			if err != nil {
				t.Fatal(err)
			}
			if len(entries) != 0 {
				t.Fatalf("metadata validation modified cache: %v", entries)
			}
		})
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
	source := p.sourceForProvisioning()
	release := source.Releases[runtime.GOARCH]
	release.ArchiveSHA256 = strings.Repeat("0", 64)
	source.Releases[runtime.GOARCH] = release
	if _, err := p.Resolve(""); err == nil || !strings.Contains(err.Error(), "configure rootfs_source") {
		t.Fatalf("digest failure = %v, want actionable cache/custom-rootfs error", err)
	}
	target := testCachePath(t, p)
	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Fatalf("failed provisioning left published rootfs: %v", err)
	}
	if temporary, _ := filepath.Glob(filepath.Join(filepath.Dir(target), ".rootfs-*")); len(temporary) != 0 {
		t.Fatalf("failed provisioning left temporary directories: %v", temporary)
	}
}

func TestProvisioningFailuresAndDigest(t *testing.T) {
	body := minimalArchive(t)
	for _, tt := range []struct {
		name      string
		status    int
		badDigest bool
		want      string
	}{
		{name: "http failure", status: http.StatusNotFound, want: "404"},
		{name: "digest mismatch", status: http.StatusOK, badDigest: true, want: "SHA-256 mismatch"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			p := testProvisioner(t, body, tt.status, nil)
			source := p.sourceForProvisioning()
			release := source.Releases[runtime.GOARCH]
			if tt.badDigest {
				release.ArchiveSHA256 = strings.Repeat("f", 64)
			}
			source.Releases[runtime.GOARCH] = release
			if _, err := p.Resolve(""); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Resolve() error = %v, want %q", err, tt.want)
			}
		})
	}
}

type interruptedReader struct {
	data []byte
	done bool
}

func (r *interruptedReader) Read(p []byte) (int, error) {
	if r.done {
		return 0, errors.New("download interrupted")
	}
	r.done = true
	return copy(p, r.data), nil
}

func TestProvisioningInterruptedDownloadLeavesNoTemporaryRootfs(t *testing.T) {
	body := minimalArchive(t)
	p := testProvisioner(t, body, http.StatusOK, nil)
	p.Client.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
		response := testResponse(http.StatusOK, nil)
		response.Body = io.NopCloser(&interruptedReader{data: body})
		return response, nil
	})
	if _, err := p.Resolve(""); err == nil || !strings.Contains(err.Error(), "download interrupted") {
		t.Fatalf("interrupted download error = %v", err)
	}
	target := testCachePath(t, p)
	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Fatalf("interrupted download left published rootfs: %v", err)
	}
	if temporary, _ := filepath.Glob(filepath.Join(filepath.Dir(target), ".rootfs-*")); len(temporary) != 0 {
		t.Fatalf("interrupted download left temporary directories: %v", temporary)
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
	var gotFlags uint
	p.renamePath = func(_ int, _ string, _ int, _ string, flags uint) error {
		gotFlags = flags
		return errors.New("rename denied")
	}
	if _, err := p.Resolve(""); err == nil || !strings.Contains(err.Error(), "atomically publish") {
		t.Fatalf("rename failure = %v", err)
	}
	if gotFlags != unix.RENAME_NOREPLACE {
		t.Fatalf("first publication flags = %#x, want RENAME_NOREPLACE", gotFlags)
	}
	target := testCachePath(t, p)
	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Fatalf("rename failure left target: %v", err)
	}
	if temporary, _ := filepath.Glob(filepath.Join(filepath.Dir(target), ".rootfs-*")); len(temporary) != 0 {
		t.Fatalf("rename failure left temporary directories: %v", temporary)
	}
}

func TestProvisioningReportsTemporaryCleanupFailure(t *testing.T) {
	body := minimalArchive(t)
	p := testProvisioner(t, body, http.StatusOK, nil)
	p.renamePath = func(_ int, _ string, toFD int, _ string, _ uint) error {
		if err := unix.Close(toFD); err != nil {
			t.Fatalf("close version directory: %v", err)
		}
		return errors.New("publish failure")
	}
	if _, err := p.Resolve(""); err == nil ||
		!strings.Contains(err.Error(), "publish failure") ||
		!strings.Contains(err.Error(), "cannot clean temporary rootfs") {
		t.Fatalf("Resolve() error = %v, want publication and cleanup failures", err)
	}
	target := testCachePath(t, p)
	temporaryPaths, err := filepath.Glob(filepath.Join(filepath.Dir(target), ".rootfs-*"))
	if err != nil {
		t.Fatal(err)
	}
	for _, temporary := range temporaryPaths {
		if err := os.RemoveAll(temporary); err != nil {
			t.Fatal(err)
		}
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

func TestHTTPSRedirectAllowsSameAndCrossHost(t *testing.T) {
	body := minimalArchive(t)
	p := testProvisioner(t, body, http.StatusOK, nil)
	var requests atomic.Int32
	redirectedURL := "https://assets.example.invalid/rootfs.tar.gz?sig=signed-token"
	p.Client.Transport = roundTripFunc(func(request *http.Request) (*http.Response, error) {
		requests.Add(1)
		if request.URL.String() == testReleaseURL {
			response := testResponse(http.StatusFound, nil)
			response.Header.Set("Location", redirectedURL)
			return response, nil
		}
		if request.URL.String() != redirectedURL {
			return nil, fmt.Errorf("unexpected redirect request %s", request.URL)
		}
		return testResponse(http.StatusOK, body), nil
	})
	if _, err := p.Resolve(""); err != nil {
		t.Fatalf("cross-host HTTPS redirect failed: %v", err)
	}
	if requests.Load() != 2 {
		t.Fatalf("cross-host redirect requests = %d, want 2", requests.Load())
	}
}

func TestCrossHostRedirectDigestMismatchDoesNotPublish(t *testing.T) {
	body := minimalArchive(t)
	p := testProvisioner(t, body, http.StatusOK, nil)
	var requests atomic.Int32
	redirectedURL := "https://assets.example.invalid/rootfs.tar.gz?sig=signed-token"
	p.Client.Transport = roundTripFunc(func(request *http.Request) (*http.Response, error) {
		requests.Add(1)
		if request.URL.String() == testReleaseURL {
			response := testResponse(http.StatusFound, nil)
			response.Header.Set("Location", redirectedURL)
			return response, nil
		}
		return testResponse(http.StatusOK, []byte("wrong archive")), nil
	})
	if _, err := p.Resolve(""); err == nil || !strings.Contains(err.Error(), "archive SHA-256 mismatch") {
		t.Fatalf("digest-mismatched redirect error = %v", err)
	}
	if requests.Load() != 2 {
		t.Fatalf("digest-mismatched redirect requests = %d, want 2", requests.Load())
	}
	if _, err := os.Stat(testCachePath(t, p)); !os.IsNotExist(err) {
		t.Fatalf("digest-mismatched redirect published cache: %v", err)
	}
}

func TestFailedRedirectErrorDoesNotExposeQuery(t *testing.T) {
	p := testProvisioner(t, minimalArchive(t), http.StatusOK, nil)
	p.Client.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
		response := testResponse(http.StatusFound, nil)
		response.Header.Set("Location", "http://assets.example.invalid/rootfs.tar.gz?sig=secret-token")
		return response, nil
	})
	_, err := p.Resolve("")
	if err == nil || strings.Contains(err.Error(), "secret-token") {
		t.Fatalf("redirect error = %v, want a sanitized failure", err)
	}
}

func TestHTTPSRedirectPolicy(t *testing.T) {
	origin, err := url.Parse(testReleaseURL)
	if err != nil {
		t.Fatal(err)
	}
	client := defaultHTTPClientFor(origin)
	tests := []struct {
		name       string
		target     string
		prior      int
		wantErr    bool
		wantSecret bool
	}{
		{name: "same origin", target: testReleaseURL + "?sig=signed-token"},
		{name: "cross-host signed query", target: "https://other.example/rootfs.tar.gz?sig=signed-token"},
		{name: "different scheme", target: "http://other.example/rootfs.tar.gz?sig=secret-token", wantErr: true},
		{name: "userinfo", target: "https://user@other.example/rootfs.tar.gz", wantErr: true},
		{name: "missing host", target: "https:///rootfs.tar.gz", wantErr: true},
		{name: "too many hops", target: testReleaseURL, prior: 3, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			target, err := url.Parse(tt.target)
			if err != nil {
				t.Fatal(err)
			}
			previous := make([]*http.Request, tt.prior)
			err = client.CheckRedirect(&http.Request{URL: target}, previous)
			if (err != nil) != tt.wantErr {
				t.Fatalf("CheckRedirect() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantSecret && err != nil && strings.Contains(err.Error(), "secret-token") {
				t.Fatalf("CheckRedirect() exposed query secret: %v", err)
			}
		})
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

func TestDownloadUsesCallerContextWithoutTotalDeadline(t *testing.T) {
	body := minimalArchive(t)
	p := testProvisioner(t, body, http.StatusOK, nil)
	p.Client = &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if _, ok := request.Context().Deadline(); ok {
			t.Error("download request unexpectedly has a total deadline")
		}
		return testResponse(http.StatusOK, body), nil
	})}
	if _, err := p.Resolve(""); err != nil {
		t.Fatalf("Resolve() = %v", err)
	}
}

func TestDefaultHTTPClientUsesSetupTimeoutsOnly(t *testing.T) {
	origin, err := url.Parse(testReleaseURL)
	if err != nil {
		t.Fatal(err)
	}
	client := defaultHTTPClientFor(origin)
	if client.Timeout != 0 {
		t.Fatalf("default client timeout = %s, want zero", client.Timeout)
	}
	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("default transport type = %T, want *http.Transport", client.Transport)
	}
	if transport.TLSHandshakeTimeout != tlsHandshakeTimeout {
		t.Fatalf("TLS handshake timeout = %s, want %s", transport.TLSHandshakeTimeout, tlsHandshakeTimeout)
	}
	if transport.ResponseHeaderTimeout != responseHeaderTimeout {
		t.Fatalf("response header timeout = %s, want %s", transport.ResponseHeaderTimeout, responseHeaderTimeout)
	}
	if dialer := defaultDialer(); dialer.Timeout != connectTimeout {
		t.Fatalf("connection timeout = %s, want %s", dialer.Timeout, connectTimeout)
	}
}

func TestProvisioningProgressEvents(t *testing.T) {
	body := minimalArchive(t)
	var events []ProgressEvent
	p := testProvisioner(t, body, http.StatusOK, nil)
	p.Progress = func(event ProgressEvent) {
		events = append(events, event)
	}
	target, err := p.Resolve("")
	if err != nil {
		t.Fatal(err)
	}
	var phases []ProgressPhase
	for _, event := range events {
		if len(phases) == 0 || phases[len(phases)-1] != event.Phase {
			phases = append(phases, event.Phase)
		}
	}
	want := []ProgressPhase{
		ProgressWaitingForCacheLock,
		ProgressValidatingCache,
		ProgressDownloadingArchive,
		ProgressExtractingFiles,
		ProgressPublishingCache,
	}
	if !reflect.DeepEqual(phases, want) {
		t.Fatalf("progress phases = %#v, want %#v", phases, want)
	}
	knownDownloadTotal := false
	for _, event := range events {
		if event.Phase == ProgressDownloadingArchive && event.Total > 0 {
			knownDownloadTotal = true
			if event.Total != int64(len(body)) {
				t.Fatalf("download total = %d, want %d", event.Total, len(body))
			}
		}
	}
	if !knownDownloadTotal {
		t.Fatal("known download total was not reported")
	}
	extractionPartial := false
	for _, event := range events {
		if event.Phase == ProgressExtractingFiles && event.Current > 0 {
			extractionPartial = true
		}
	}
	if !extractionPartial {
		t.Fatal("extraction progress was not reported during file copying")
	}
	events = nil
	if got, err := p.Resolve(""); err != nil || got != target {
		t.Fatalf("cached Resolve() = %q, %v; want %q, nil", got, err, target)
	}
	for _, event := range events {
		if event.Phase != ProgressWaitingForCacheLock && event.Phase != ProgressValidatingCache {
			t.Fatalf("cache hit emitted phase %q", event.Phase)
		}
	}

	p = testProvisioner(t, body, http.StatusOK, nil)
	var unknownTotal bool
	p.Progress = func(event ProgressEvent) {
		if event.Phase == ProgressDownloadingArchive && event.Total == 0 {
			unknownTotal = true
		}
	}
	p.Client.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
		response := testResponse(http.StatusOK, body)
		response.ContentLength = -1
		return response, nil
	})
	if _, err := p.Resolve(""); err != nil {
		t.Fatal(err)
	}
	if !unknownTotal {
		t.Fatal("unknown download total was not reported")
	}
}

func TestProgressWaitingEventPrecedesCacheLock(t *testing.T) {
	body := minimalArchive(t)
	p := testProvisioner(t, body, http.StatusOK, nil)
	source := p.sourceForProvisioning()
	_, versionFD, err := ensureManagedVersionDir(p.CacheDir, source)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(versionFD)
	lock, err := acquireLockAt(versionFD)
	if err != nil {
		t.Fatal(err)
	}

	events := make(chan ProgressEvent, 32)
	p.Progress = func(event ProgressEvent) {
		events <- event
	}
	done := make(chan error, 1)
	go func() {
		_, err := p.Resolve("")
		done <- err
	}()
	select {
	case event := <-events:
		if event.Phase != ProgressWaitingForCacheLock {
			t.Fatalf("first blocked provisioning event = %q, want waiting for cache lock", event.Phase)
		}
	case <-time.After(time.Second):
		t.Fatal("waiting-for-lock progress event was not emitted while lock was held")
	}
	if err := lock.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("provisioning after releasing cache lock = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("provisioning did not continue after releasing cache lock")
	}
}

type progressSyntheticFileInfo struct {
	mode fs.FileMode
	size int64
}

func (f progressSyntheticFileInfo) Name() string       { return "synthetic" }
func (f progressSyntheticFileInfo) Size() int64        { return f.size }
func (f progressSyntheticFileInfo) Mode() fs.FileMode  { return f.mode }
func (f progressSyntheticFileInfo) ModTime() time.Time { return time.Time{} }
func (f progressSyntheticFileInfo) IsDir() bool        { return f.mode.IsDir() }
func (f progressSyntheticFileInfo) Sys() any           { return nil }

type progressChunkFile struct {
	data []byte
	info fs.FileInfo
}

func (f *progressChunkFile) Read(buffer []byte) (int, error) {
	if len(f.data) == 0 {
		return 0, io.EOF
	}
	if len(buffer) > 2 {
		buffer = buffer[:2]
	}
	n := copy(buffer, f.data)
	f.data = f.data[n:]
	return n, nil
}

func (f *progressChunkFile) Close() error               { return nil }
func (f *progressChunkFile) Stat() (fs.FileInfo, error) { return f.info, nil }

func TestExtractionProgressDuringFileCopies(t *testing.T) {
	data := bytes.Repeat([]byte("x"), 64<<10)
	info := progressSyntheticFileInfo{mode: 0600, size: int64(len(data))}
	destination := t.TempDir()
	var progress []int64
	extractedBytes := int64(0)
	file := archives.FileInfo{
		FileInfo: info,
		Open: func() (fs.File, error) {
			return &progressChunkFile{data: append([]byte(nil), data...), info: info}, nil
		},
	}
	if err := extractRegularFile(destination, "file", file, defaultRootfsLimits, &extractedBytes, func(current int64) {
		progress = append(progress, current)
	}); err != nil {
		t.Fatal(err)
	}
	if len(progress) < 2 || progress[len(progress)-1] != int64(len(data)) {
		t.Fatalf("extraction progress = %#v, want partial updates ending at %d", progress, len(data))
	}
}

func TestSecureExtraction(t *testing.T) {
	tests := []struct {
		name    string
		entries []archiveEntry
		limits  rootfsLimits
		want    string
	}{
		{name: "absolute path", entries: []archiveEntry{{name: "/etc/passwd", kind: tar.TypeReg, mode: 0644, body: []byte("x")}}, want: "absolute"},
		{name: "parent traversal", entries: []archiveEntry{{name: "../escape", kind: tar.TypeReg, mode: 0644, body: []byte("x")}}, want: "safe relative"},
		{name: "escaping symlink", entries: []archiveEntry{{name: "etc/link", kind: tar.TypeSymlink, mode: 0777, link: "../../outside"}}, want: "escapes"},
		{name: "symlink parent", entries: []archiveEntry{{name: "bin", kind: tar.TypeSymlink, mode: 0777, link: "."}, {name: "bin/file", kind: tar.TypeReg, mode: 0644, body: []byte("x")}}, want: "non-directory"},
		{name: "duplicate", entries: []archiveEntry{{name: "file", kind: tar.TypeReg, mode: 0644, body: []byte("a")}, {name: "file", kind: tar.TypeReg, mode: 0644, body: []byte("b")}}, want: "duplicate"},
		{name: "hard link outside", entries: []archiveEntry{{name: "link", kind: tar.TypeLink, mode: 0644, link: "../outside"}}, want: "invalid target"},
		{name: "device node", entries: []archiveEntry{{name: "dev/null", kind: tar.TypeChar, mode: 0600}}, want: "unsupported type"},
		{name: "file too large", entries: []archiveEntry{{name: "file", kind: tar.TypeReg, mode: 0644, body: []byte("123")}}, limits: rootfsLimits{MaxTotalBytes: 1 << 20, MaxFileBytes: 2, MaxEntries: 10}, want: "file limit"},
		{name: "total too large", entries: []archiveEntry{{name: "one", kind: tar.TypeReg, mode: 0644, body: []byte("123")}, {name: "two", kind: tar.TypeReg, mode: 0644, body: []byte("456")}}, limits: rootfsLimits{MaxTotalBytes: 5, MaxFileBytes: 10, MaxEntries: 10}, want: "extracted-data limit"},
		{name: "too many entries", entries: []archiveEntry{{name: "one", kind: tar.TypeReg, mode: 0644, body: []byte("1")}, {name: "two", kind: tar.TypeReg, mode: 0644, body: []byte("2")}}, limits: rootfsLimits{MaxTotalBytes: 1 << 20, MaxFileBytes: 10, MaxEntries: 1}, want: "entry limit"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			archive := makeArchive(t, tt.entries...)
			archivePath := filepath.Join(t.TempDir(), "archive.tar.gz")
			if err := os.WriteFile(archivePath, archive, 0600); err != nil {
				t.Fatal(err)
			}
			limits := tt.limits
			if limits.MaxTotalBytes == 0 {
				limits = defaultRootfsLimits
			}
			destination := filepath.Join(t.TempDir(), "rootfs")
			if err := os.Mkdir(destination, 0700); err != nil {
				t.Fatal(err)
			}
			err := extractArchiveForTest(archivePath, destination, limits)
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
	if err := extractArchiveForTest(archivePath, root, defaultRootfsLimits); err == nil || !strings.Contains(err.Error(), "root marker") {
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
	if err := extractArchiveForTest(archivePath, destination, defaultRootfsLimits); err != nil {
		t.Fatalf("extractArchive() error = %v", err)
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
	err := extractArchiveForTest(archivePath, filepath.Join(t.TempDir(), "rootfs"), defaultRootfsLimits)
	if err == nil || !strings.Contains(err.Error(), "identify") {
		t.Fatalf("extractArchive() error = %v, want archive-identification error", err)
	}
}

func TestExtractionReportsStatistics(t *testing.T) {
	archivePath := filepath.Join(t.TempDir(), "archive.tar.gz")
	archive := makeArchive(t,
		archiveEntry{name: "./", kind: tar.TypeDir, mode: 0755},
		archiveEntry{name: "one", kind: tar.TypeReg, mode: 0600, body: []byte("123")},
		archiveEntry{name: "two", kind: tar.TypeReg, mode: 0600, body: []byte("12345")},
	)
	if err := os.WriteFile(archivePath, archive, 0600); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(t.TempDir(), "rootfs")
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	stats, err := extractArchive(archivePath, root, defaultRootfsLimits)
	if err != nil {
		t.Fatal(err)
	}
	if stats.TotalBytes != 8 || stats.LargestFileBytes != 5 || stats.Entries != 3 {
		t.Fatalf("extraction stats = %+v, want total=8 largest=5 entries=3", stats)
	}
}

func TestExtractRecognizedArchiveFormats(t *testing.T) {
	entries := []archiveEntry{
		{name: "./", kind: tar.TypeDir, mode: 0755},
		{name: "./bin/", kind: tar.TypeDir, mode: 0755},
		{name: "./bin/hello", kind: tar.TypeReg, mode: 0755, body: []byte("hello")},
	}
	tarBytes := makeTarArchive(t, entries...)
	compressedTar := makeArchive(t, entries...)
	tests := []struct {
		name string
		body []byte
	}{
		{name: "tar", body: tarBytes},
		{name: "gzip tar", body: compressedTar},
		{name: "zstd tar", body: makeZstdArchive(t, tarBytes)},
		{name: "zip", body: makeZipArchive(t, entries...)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			archivePath := filepath.Join(t.TempDir(), "input")
			if err := os.WriteFile(archivePath, tt.body, 0600); err != nil {
				t.Fatal(err)
			}
			root := filepath.Join(t.TempDir(), "rootfs")
			if err := os.Mkdir(root, 0700); err != nil {
				t.Fatal(err)
			}
			if err := extractArchiveForTest(archivePath, root, defaultRootfsLimits); err != nil {
				t.Fatalf("extractArchive() error = %v", err)
			}
		})
	}

	archivePath := filepath.Join(t.TempDir(), "invalid")
	if err := os.WriteFile(archivePath, []byte("not an archive"), 0600); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(t.TempDir(), "rootfs")
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	if err := extractArchiveForTest(archivePath, root, defaultRootfsLimits); err == nil {
		t.Fatal("extractArchive() accepted an unrecognized stream")
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
	if err := validatePublishedRootfsForTest(target, p.sourceForProvisioning(), p.sourceForProvisioning().Releases[runtime.GOARCH]); err == nil {
		t.Fatal("validatePublishedRootfs() accepted unexpected manifest field")
	}
}

func TestManifestValidationIsBounded(t *testing.T) {
	body := minimalArchive(t)
	p := testProvisioner(t, body, http.StatusOK, nil)
	target, err := p.Resolve("")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, manifestName), bytes.Repeat([]byte("x"), maxManifestBytes+1), 0600); err != nil {
		t.Fatal(err)
	}
	if err := validatePublishedRootfsForTest(target, p.sourceForProvisioning(), p.sourceForProvisioning().Releases[runtime.GOARCH]); err == nil || !strings.Contains(err.Error(), "manifest exceeds") {
		t.Fatalf("validatePublishedRootfs() error = %v, want bounded manifest error", err)
	}
}

func TestRemoveTreeAtUsesBoundedBatches(t *testing.T) {
	parent := t.TempDir()
	target := filepath.Join(parent, "tree")
	if err := os.Mkdir(target, 0700); err != nil {
		t.Fatal(err)
	}
	for name, mode := range map[string]os.FileMode{"zero": 0000, "execute": 0111} {
		directory := filepath.Join(target, name)
		if err := os.Mkdir(directory, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(directory, "file"), []byte("x"), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(directory, mode); err != nil {
			t.Fatal(err)
		}
	}
	external := t.TempDir()
	marker := filepath.Join(external, "marker")
	if err := os.WriteFile(marker, []byte("unchanged"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(external, filepath.Join(target, "external")); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < cleanupDirectoryBatch*2+1; i++ {
		name := filepath.Join(target, fmt.Sprintf("entry-%03d", i))
		if err := os.WriteFile(name, []byte("x"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	parentFD, err := openDirectoryPath(parent)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(parentFD)
	if err := removeTreeAt(parentFD, "tree"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(target); !os.IsNotExist(err) {
		t.Fatalf("removeTreeAt() left tree: %v", err)
	}
	if got, err := os.ReadFile(marker); err != nil || string(got) != "unchanged" {
		t.Fatalf("cleanup followed external symlink: err=%v data=%q", err, got)
	}
}

func TestReplacementExchangeFailurePreservesPreviousRootfs(t *testing.T) {
	body := minimalArchive(t)
	p := testProvisioner(t, body, http.StatusOK, nil)
	target, err := p.Resolve("")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, manifestName), []byte("{}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	var gotFlags uint
	p.renamePath = func(_ int, _ string, _ int, _ string, flags uint) error {
		gotFlags = flags
		return errors.New("replacement interrupted")
	}
	if _, err := p.Resolve(""); err == nil || !strings.Contains(err.Error(), "replacement interrupted") {
		t.Fatalf("Resolve() error = %v, want replacement failure", err)
	}
	if gotFlags != unix.RENAME_EXCHANGE {
		t.Fatalf("replacement flags = %#x, want RENAME_EXCHANGE", gotFlags)
	}
	if data, err := os.ReadFile(filepath.Join(target, manifestName)); err != nil || string(data) != "{}\n" {
		t.Fatalf("previous rootfs was not restored: err=%v data=%q", err, data)
	}
	if temporary, _ := filepath.Glob(filepath.Join(filepath.Dir(target), ".rootfs-*")); len(temporary) != 0 {
		t.Fatalf("replacement left temporary directories: %v", temporary)
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
		managedVersion := filepath.Join(cache, "bcs-zc241t-sandbox", "rootfs", defaultManagedSource.Provider, defaultManagedSource.Version)
		if err := os.MkdirAll(managedVersion, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(filepath.Join(t.TempDir(), "lock"), filepath.Join(managedVersion, lockName)); err != nil {
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
	want := map[string]struct {
		alpineArch string
		cacheKey   string
		archive    string
		sha256     string
	}{
		"amd64": {
			alpineArch: "x86_64",
			cacheKey:   "x86_64",
			archive:    "alpine-minirootfs-3.24.1-x86_64.tar.gz",
			sha256:     "41f73e3cf5fa919b8aa5ca6b30dc48f0da2720776d7423e2a7748211456fe081",
		},
		"arm64": {
			alpineArch: "aarch64",
			cacheKey:   "aarch64",
			archive:    "alpine-minirootfs-3.24.1-aarch64.tar.gz",
			sha256:     "f55a90f69052c5bd6f92cb09a8f47065970830b194c917a006fb94028e721259",
		},
	}
	for goArch, expected := range want {
		release, ok := defaultManagedSource.Releases[goArch]
		if !ok || release.Architecture != expected.alpineArch || release.CacheKey != expected.cacheKey || release.ArchiveName != expected.archive || release.ArchiveSHA256 != expected.sha256 {
			t.Errorf("defaultManagedSource.Releases[%q] = %+v, want %+v", goArch, release, expected)
		}
	}
}

func TestRemoteRootfsLimits(t *testing.T) {
	defaults, err := remoteRootfsLimits(RemoteSource{})
	if err != nil {
		t.Fatal(err)
	}
	if defaults != (rootfsLimits{MaxTotalBytes: 512 << 20, MaxFileBytes: 128 << 20, MaxEntries: 100000}) {
		t.Fatalf("default remote limits = %#v", defaults)
	}
	overridden, err := remoteRootfsLimits(RemoteSource{
		MaxExtractedSizeMB: 2048,
		MaxFileSizeMB:      256,
		MaxEntries:         7,
	})
	if err != nil {
		t.Fatal(err)
	}
	if overridden != (rootfsLimits{MaxTotalBytes: 2048 << 20, MaxFileBytes: 256 << 20, MaxEntries: 7}) {
		t.Fatalf("overridden remote limits = %#v", overridden)
	}
	for _, remote := range []RemoteSource{
		{MaxExtractedSizeMB: -1},
		{MaxFileSizeMB: -1},
		{MaxEntries: -1},
		{MaxExtractedSizeMB: int(^uint(0) >> 1)},
		{MaxExtractedSizeMB: 1, MaxFileSizeMB: 2},
	} {
		if _, err := remoteRootfsLimits(remote); err == nil {
			t.Errorf("remoteRootfsLimits(%+v) accepted invalid limits", remote)
		}
	}
}

func TestTreeLimitsCanBeRaisedForLargerRemoteRoots(t *testing.T) {
	body := makeArchive(t,
		archiveEntry{name: "one", kind: tar.TypeReg, mode: 0644, body: []byte("1")},
		archiveEntry{name: "two", kind: tar.TypeReg, mode: 0644, body: []byte("2")},
	)
	archivePath := filepath.Join(t.TempDir(), "archive")
	if err := os.WriteFile(archivePath, body, 0600); err != nil {
		t.Fatal(err)
	}
	small := rootfsLimits{MaxTotalBytes: 1, MaxFileBytes: 1, MaxEntries: 10}
	root := filepath.Join(t.TempDir(), "small")
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := extractArchive(archivePath, root, small); err == nil {
		t.Fatal("small tree limits accepted the archive")
	}
	large := rootfsLimits{MaxTotalBytes: 1 << 20, MaxFileBytes: 1 << 20, MaxEntries: 10}
	root = filepath.Join(t.TempDir(), "large")
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	stats, err := extractArchive(archivePath, root, large)
	if err != nil {
		t.Fatalf("larger tree limits rejected the archive: %v", err)
	}
	if stats != (extractionStats{TotalBytes: 2, LargestFileBytes: 1, Entries: 2}) {
		t.Fatalf("extraction stats = %#v", stats)
	}
}

func TestReleaseURLValidation(t *testing.T) {
	valid := "https://dl-cdn.alpinelinux.org/alpine/v3.24/releases/x86_64/rootfs.tar.gz"
	if _, err := validateReleaseURL(valid); err != nil {
		t.Fatalf("valid release URL rejected: %v", err)
	}
	if _, err := validateReleaseURL("https://mirror.example/releases/rootfs.tar.gz"); err != nil {
		t.Fatalf("provider-neutral release URL rejected: %v", err)
	}
	for _, raw := range []string{
		"http://dl-cdn.alpinelinux.org/rootfs.tar.gz",
		"https://user:pass@dl-cdn.alpinelinux.org/rootfs.tar.gz",
		"https://dl-cdn.alpinelinux.org/rootfs.tar.gz?redirect=1",
		"https://dl-cdn.alpinelinux.org/alpine/../rootfs.tar.gz",
	} {
		if _, err := validateReleaseURL(raw); err == nil {
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

func TestExplicitRootfsValidation(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "nested"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "file"), []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(root, filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "parent"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(root, filepath.Join(root, "parent", "link")); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		path string
	}{
		{name: "relative", path: "relative-rootfs"},
		{name: "final symlink", path: filepath.Join(root, "link")},
		{name: "intermediate symlink", path: filepath.Join(root, "parent", "link", "nested")},
		{name: "regular file", path: filepath.Join(root, "file")},
		{name: "parent component", path: root + "/nested/../nested"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := validateExplicitRootfs(tt.path); err == nil {
				t.Fatalf("validateExplicitRootfs(%q) accepted unsafe path", tt.path)
			}
		})
	}
}
