//go:build linux

// Package rootfs provisions and verifies the sandbox's managed rootfs.
package rootfs

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

const (
	manifestName          = "manifest.json"
	lockName              = ".lock"
	manifestSchemaVersion = 1

	connectTimeout        = 10 * time.Second
	tlsHandshakeTimeout   = 10 * time.Second
	responseHeaderTimeout = 30 * time.Second
	maxManifestBytes      = 4 << 10
)

type managedSource struct {
	Provider string
	Version  string
	Releases map[string]managedRelease
}

type managedRelease struct {
	Architecture  string
	CacheKey      string
	ArchiveName   string
	URL           string
	ArchiveSHA256 string
}

// RemoteSource describes a user-supplied archive whose identity is pinned by
// its archive digest.
type RemoteSource struct {
	URL           string
	Architecture  string
	ArchiveSHA256 string
}

var defaultManagedSource = managedSource{
	Provider: "alpine",
	Version:  "3.24.1",
	Releases: map[string]managedRelease{
		"amd64": {
			Architecture:  "x86_64",
			CacheKey:      "x86_64",
			ArchiveName:   "alpine-minirootfs-3.24.1-x86_64.tar.gz",
			URL:           "https://dl-cdn.alpinelinux.org/alpine/v3.24/releases/x86_64/alpine-minirootfs-3.24.1-x86_64.tar.gz",
			ArchiveSHA256: "41f73e3cf5fa919b8aa5ca6b30dc48f0da2720776d7423e2a7748211456fe081",
		},
		"arm64": {
			Architecture:  "aarch64",
			CacheKey:      "aarch64",
			ArchiveName:   "alpine-minirootfs-3.24.1-aarch64.tar.gz",
			URL:           "https://dl-cdn.alpinelinux.org/alpine/v3.24/releases/aarch64/alpine-minirootfs-3.24.1-aarch64.tar.gz",
			ArchiveSHA256: "f55a90f69052c5bd6f92cb09a8f47065970830b194c917a006fb94028e721259",
		},
	},
}

// Provisioner resolves explicit rootfs paths or provisions the managed
// rootfs in the user's cache. Client may be supplied by hermetic tests;
// the zero value uses the setup-timeout- and redirect-checked default client.
type Provisioner struct {
	CacheDir string
	Client   *http.Client

	// source is intentionally private: tests replace the catalog with small
	// synthetic archives, while production uses the pinned default above.
	source     *managedSource
	makeTemp   func(string, string) (string, error)
	renamePath func(int, string, int, string, uint) error
}

func (p Provisioner) sourceForProvisioning() managedSource {
	if p.source != nil {
		return *p.source
	}
	return defaultManagedSource
}

func cachePath(cacheDir string, source managedSource, release managedRelease) (string, error) {
	if cacheDir == "" {
		return "", fmt.Errorf("cache directory cannot be empty")
	}
	if release.CacheKey == "" {
		return "", fmt.Errorf("managed rootfs cache key cannot be empty")
	}
	return filepath.Join(cacheDir, "bcs-zc241t-sandbox", "rootfs", source.Provider, source.Version, release.CacheKey), nil
}

// Resolve returns a validated explicit rootfs or the completed managed rootfs.
// Explicit paths never access the cache or network.
func (p Provisioner) Resolve(rootfsSource string) (string, error) {
	if rootfsSource != "" {
		return validateExplicitRootfs(rootfsSource)
	}
	managed := p.sourceForProvisioning()
	goArch := runtime.GOARCH
	release, ok := managed.Releases[goArch]
	if !ok {
		return "", fmt.Errorf("unsupported sandbox architecture %q", goArch)
	}
	if err := validateManagedMetadata(managed, release); err != nil {
		return "", err
	}
	return p.resolveManaged(managed, release, defaultRootfsLimits)
}

// ResolveRemote provisions or reuses a verified remote rootfs. The archive
// digest is the cache identity, so changing mirrors does not duplicate it.
func (p Provisioner) ResolveRemote(remote RemoteSource) (string, error) {
	if remote.Architecture != runtime.GOARCH {
		return "", fmt.Errorf("remote rootfs architecture %q does not match runtime architecture %q", remote.Architecture, runtime.GOARCH)
	}
	managed := managedSource{Provider: "remote", Version: "v1"}
	release := managedRelease{
		Architecture:  remote.Architecture,
		CacheKey:      remote.ArchiveSHA256,
		ArchiveName:   "rootfs.tar.gz",
		URL:           remote.URL,
		ArchiveSHA256: remote.ArchiveSHA256,
	}
	managed.Releases = map[string]managedRelease{runtime.GOARCH: release}
	if err := validateManagedMetadata(managed, release); err != nil {
		return "", err
	}
	return p.resolveManaged(managed, release, defaultRootfsLimits)
}

func (p Provisioner) resolveManaged(managed managedSource, release managedRelease, limits rootfsLimits) (string, error) {

	cacheDir := p.CacheDir
	if cacheDir == "" {
		var err error
		cacheDir, err = os.UserCacheDir()
		if err != nil {
			return "", fmt.Errorf("cannot determine user cache directory: %v", err)
		}
	}
	target, err := cachePath(cacheDir, managed, release)
	if err != nil {
		return "", err
	}
	return p.provision(cacheDir, target, managed, release, limits)
}

func validateManagedMetadata(source managedSource, release managedRelease) error {
	for name, value := range map[string]string{
		"provider":     source.Provider,
		"version":      source.Version,
		"architecture": release.Architecture,
		"cache key":    release.CacheKey,
		"archive name": release.ArchiveName,
	} {
		if value == "" || strings.ContainsRune(value, 0) || strings.Contains(value, "/") || value == "." || value == ".." {
			return fmt.Errorf("managed rootfs %s must be a non-empty path component", name)
		}
	}
	if err := validateDigest("archive SHA-256", release.ArchiveSHA256); err != nil {
		return err
	}
	if _, err := validateReleaseURL(release.URL); err != nil {
		return fmt.Errorf("invalid managed rootfs release URL: %w", err)
	}
	return nil
}

func validateDigest(name, value string) error {
	if len(value) != sha256.Size*2 || value != strings.ToLower(value) {
		return fmt.Errorf("managed rootfs %s must be a canonical 32-byte hexadecimal digest", name)
	}
	if _, err := hex.DecodeString(value); err != nil {
		return fmt.Errorf("managed rootfs %s must be a canonical 32-byte hexadecimal digest: %v", name, err)
	}
	return nil
}

func validateExplicitRootfs(source string) (string, error) {
	fd, err := openDirectoryPath(source)
	if err != nil {
		return "", fmt.Errorf("configured rootfs_source %q is unavailable: %v", source, err)
	}
	defer unix.Close(fd)
	return source, nil
}

func (p Provisioner) provision(cacheDir, target string, source managedSource, release managedRelease, limits rootfsLimits) (result string, err error) {
	versionDir, versionFD, err := ensureManagedVersionDir(cacheDir, source)
	if err != nil {
		return "", p.provisionError(release, target, err)
	}
	defer unix.Close(versionFD)
	target = filepath.Join(versionDir, release.CacheKey)

	lock, err := acquireLockAt(versionFD)
	if err != nil {
		return "", p.provisionError(release, target, fmt.Errorf("cannot lock cache: %v", err))
	}
	defer lock.Close()

	targetName := release.CacheKey
	if err := validatePublishedRootfsAt(versionFD, targetName, source, release, limits); err == nil {
		return target, nil
	}

	makeTemp := p.makeTemp
	if makeTemp == nil {
		makeTemp = os.MkdirTemp
	}
	temporary, err := makeTemp(versionDir, ".rootfs-")
	if err != nil {
		return "", p.provisionError(release, target, fmt.Errorf("cannot create temporary cache directory: %v", err))
	}
	temporaryName := filepath.Base(temporary)
	defer func() {
		if cleanupErr := removeManagedTreeAt(versionFD, temporaryName); cleanupErr != nil {
			err = errors.Join(err, fmt.Errorf("cannot clean temporary rootfs: %w", cleanupErr))
		}
	}()

	archivePath := filepath.Join(temporary, release.ArchiveName)
	if err := p.download(context.Background(), release, archivePath); err != nil {
		return "", p.provisionError(release, target, err)
	}

	extracted := filepath.Join(temporary, "rootfs")
	if err := os.Mkdir(extracted, 0700); err != nil {
		return "", p.provisionError(release, target, fmt.Errorf("cannot create extraction directory: %v", err))
	}
	stats, err := extractArchive(archivePath, extracted, limits)
	if err != nil {
		return "", p.provisionError(release, target, err)
	}
	if err := os.Remove(archivePath); err != nil {
		return "", p.provisionError(release, target, fmt.Errorf("cannot remove downloaded archive: %w", err))
	}
	if err := writeManifest(extracted, source, release, stats); err != nil {
		return "", p.provisionError(release, target, err)
	}
	if err := syncDirectoryPath(extracted, "completed rootfs"); err != nil {
		return "", p.provisionError(release, target, err)
	}
	if err := publishReplacement(versionFD, temporaryName, targetName, p.renamePath); err != nil {
		return "", p.provisionError(release, target, err)
	}
	if err := syncDirectory(versionFD, versionDir); err != nil {
		return "", p.provisionError(release, target, err)
	}
	return target, nil
}

func (p Provisioner) provisionError(release managedRelease, target string, err error) error {
	return fmt.Errorf("managed rootfs provisioning failed from %s: %v; cache: %s; configure rootfs_source to use a custom rootfs", release.URL, err, target)
}

func (p Provisioner) download(ctx context.Context, release managedRelease, destination string) error {
	origin, err := validateReleaseURL(release.URL)
	if err != nil {
		return err
	}
	client := p.Client
	if client == nil {
		client = defaultHTTPClientFor(origin)
	} else {
		clone := *client
		if clone.Transport == nil {
			clone.Transport = defaultHTTPClientFor(origin).Transport
		}
		clone.CheckRedirect = redirectPolicy(origin)
		client = &clone
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, release.URL, nil)
	if err != nil {
		return fmt.Errorf("cannot create download request: %v", err)
	}
	response, err := client.Do(request)
	if err != nil {
		return safeDownloadError(request.URL, err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("download returned HTTP status %s", response.Status)
	}
	file, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return fmt.Errorf("cannot create archive temporary file: %v", err)
	}
	remove := true
	defer func() {
		file.Close()
		if remove {
			os.Remove(destination)
		}
	}()

	hash := sha256.New()
	_, err = io.Copy(io.MultiWriter(file, hash), response.Body)
	if err != nil {
		return fmt.Errorf("cannot save downloaded archive: %v", err)
	}
	if got := hex.EncodeToString(hash.Sum(nil)); got != release.ArchiveSHA256 {
		return fmt.Errorf("archive SHA-256 mismatch: got %s, want %s", got, release.ArchiveSHA256)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("cannot close downloaded archive: %v", err)
	}
	remove = false
	return nil
}

func defaultHTTPClientFor(origin *url.URL) *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.DialContext = defaultDialer().DialContext
	transport.TLSHandshakeTimeout = tlsHandshakeTimeout
	transport.ResponseHeaderTimeout = responseHeaderTimeout
	return &http.Client{
		Transport:     transport,
		CheckRedirect: redirectPolicy(origin),
	}
}

func defaultDialer() *net.Dialer {
	return &net.Dialer{Timeout: connectTimeout}
}

func validateReleaseURL(raw string) (*url.URL, error) {
	parsed, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("invalid rootfs source URL: %v", err)
	}
	if parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, fmt.Errorf("rootfs source URL must be an HTTPS URL without userinfo, query, or fragment")
	}
	if parsed.Path == "" || !strings.HasPrefix(parsed.Path, "/") || parsed.Path != path.Clean(parsed.Path) || strings.ContainsRune(parsed.Path, 0) || strings.Contains(parsed.Path, "..") {
		return nil, fmt.Errorf("rootfs source URL has an unsafe release path")
	}
	return parsed, nil
}

func safeURLString(raw *url.URL) string {
	if raw == nil {
		return "<unknown URL>"
	}
	safe := *raw
	safe.User = nil
	safe.RawQuery = ""
	safe.ForceQuery = false
	safe.Fragment = ""
	return safe.String()
}

type redirectError struct {
	message string
}

func (e *redirectError) Error() string { return e.message }

func safeDownloadError(requestURL *url.URL, err error) error {
	var redirectErr *redirectError
	if errors.As(err, &redirectErr) {
		return fmt.Errorf("download request failed for %s: %s", safeURLString(requestURL), redirectErr)
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("download request failed for %s: request timed out", safeURLString(requestURL))
	}
	var urlErr *url.Error
	if errors.As(err, &urlErr) && urlErr.Err != nil {
		err = urlErr.Err
	}
	message := err.Error()
	if strings.Contains(message, "://") || strings.ContainsAny(message, "?#") {
		message = "transport error"
	}
	return fmt.Errorf("download request failed for %s: %s", safeURLString(requestURL), message)
}

func redirectPolicy(origin *url.URL) func(*http.Request, []*http.Request) error {
	return func(request *http.Request, previous []*http.Request) error {
		if len(previous) >= 3 {
			return &redirectError{message: fmt.Sprintf("refusing redirect after %d hops", len(previous))}
		}
		if request.URL == nil || request.URL.Hostname() == "" {
			return &redirectError{message: "refusing redirect with a missing host"}
		}
		if request.URL.Scheme != "https" || (origin != nil && request.URL.Scheme != origin.Scheme) {
			return &redirectError{message: fmt.Sprintf("refusing redirect to a non-HTTPS URL %s", safeURLString(request.URL))}
		}
		if request.URL.User != nil {
			return &redirectError{message: fmt.Sprintf("refusing redirect with userinfo in %s", safeURLString(request.URL))}
		}
		return nil
	}
}

type manifest struct {
	SchemaVersion    int    `json:"schema_version"`
	Provider         string `json:"provider"`
	Version          string `json:"version"`
	Architecture     string `json:"architecture"`
	Archive          string `json:"archive"`
	SHA256           string `json:"sha256"`
	ExtractedBytes   int64  `json:"extracted_bytes"`
	LargestFileBytes int64  `json:"largest_file_bytes"`
	Entries          int    `json:"entries"`
}

func manifestFor(source managedSource, release managedRelease, stats extractionStats) manifest {
	return manifest{
		SchemaVersion:    manifestSchemaVersion,
		Provider:         source.Provider,
		Version:          source.Version,
		Architecture:     release.Architecture,
		Archive:          release.ArchiveName,
		SHA256:           release.ArchiveSHA256,
		ExtractedBytes:   stats.TotalBytes,
		LargestFileBytes: stats.LargestFileBytes,
		Entries:          stats.Entries,
	}
}

func writeManifest(root string, source managedSource, release managedRelease, stats extractionStats) error {
	data, err := json.MarshalIndent(manifestFor(source, release, stats), "", "  ")
	if err != nil {
		return fmt.Errorf("cannot encode rootfs manifest: %v", err)
	}
	data = append(data, '\n')
	rootFD, err := openDirectoryPath(root)
	if err != nil {
		return fmt.Errorf("cannot open rootfs for manifest: %v", err)
	}
	defer unix.Close(rootFD)
	fd, err := unix.Openat(rootFD, manifestName, unix.O_WRONLY|unix.O_CREAT|unix.O_TRUNC|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return fmt.Errorf("cannot write rootfs manifest: %v", err)
	}
	file := os.NewFile(uintptr(fd), manifestName)
	if file == nil {
		unix.Close(fd)
		return fmt.Errorf("cannot open rootfs manifest")
	}
	if err := file.Chmod(0600); err != nil {
		file.Close()
		return fmt.Errorf("cannot set rootfs manifest mode: %v", err)
	}
	if _, err := file.Write(data); err != nil {
		file.Close()
		return fmt.Errorf("cannot write rootfs manifest: %v", err)
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return fmt.Errorf("cannot fsync rootfs manifest: %v", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("cannot close rootfs manifest: %v", err)
	}
	if err := syncDirectory(rootFD, "rootfs"); err != nil {
		return err
	}
	return nil
}

func validatePublishedRootfs(root string, source managedSource, release managedRelease, limits rootfsLimits) error {
	rootFD, err := openDirectoryPath(root)
	if err != nil {
		return err
	}
	defer unix.Close(rootFD)
	return validatePublishedRootfsFD(rootFD, source, release, limits)
}

func validatePublishedRootfsAt(versionFD int, targetName string, source managedSource, release managedRelease, limits rootfsLimits) error {
	rootFD, err := openDirectoryAt(versionFD, targetName)
	if err != nil {
		return err
	}
	defer unix.Close(rootFD)
	return validatePublishedRootfsFD(rootFD, source, release, limits)
}

func validatePublishedRootfsFD(rootFD int, source managedSource, release managedRelease, limits rootfsLimits) error {
	if err := validateManagedDirectory(rootFD, "published rootfs"); err != nil {
		return err
	}
	fd, err := unix.Openat(rootFD, manifestName, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return fmt.Errorf("cannot open rootfs manifest without following symlinks: %v", err)
	}
	file := os.NewFile(uintptr(fd), manifestName)
	if file == nil {
		unix.Close(fd)
		return fmt.Errorf("cannot open rootfs manifest")
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		file.Close()
		return err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Uid != uint32(os.Getuid()) || stat.Mode&0777 != 0600 {
		file.Close()
		return fmt.Errorf("rootfs manifest has unsafe type, ownership, or mode")
	}
	data, err := io.ReadAll(io.LimitReader(file, maxManifestBytes+1))
	closeErr := file.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if len(data) > maxManifestBytes {
		return fmt.Errorf("rootfs manifest exceeds the %d-byte limit", maxManifestBytes)
	}
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	var got manifest
	if err := decoder.Decode(&got); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return fmt.Errorf("rootfs manifest contains trailing data")
		}
		return err
	}
	expected := manifestFor(source, release, extractionStats{})
	if got.SchemaVersion != manifestSchemaVersion || got.Provider != expected.Provider || got.Version != expected.Version ||
		got.Architecture != expected.Architecture || got.Archive != expected.Archive ||
		got.SHA256 != expected.SHA256 {
		return fmt.Errorf("rootfs manifest does not match pinned release")
	}
	if got.ExtractedBytes < 0 || got.LargestFileBytes < 0 || got.Entries < 0 || got.LargestFileBytes > got.ExtractedBytes {
		return fmt.Errorf("rootfs manifest contains invalid extraction statistics")
	}
	if got.ExtractedBytes > limits.MaxTotalBytes {
		return fmt.Errorf("rootfs manifest exceeds the %d-byte extracted-data limit", limits.MaxTotalBytes)
	}
	if got.LargestFileBytes > limits.MaxFileBytes {
		return fmt.Errorf("rootfs manifest exceeds the %d-byte file limit", limits.MaxFileBytes)
	}
	if got.Entries > limits.MaxEntries {
		return fmt.Errorf("rootfs manifest exceeds the %d-entry limit", limits.MaxEntries)
	}
	return nil
}

func syncDirectoryPath(path, label string) error {
	fd, err := openDirectoryPath(path)
	if err != nil {
		return fmt.Errorf("cannot open %s for fsync: %v", label, err)
	}
	defer unix.Close(fd)
	return syncDirectory(fd, label)
}

func publishReplacement(versionFD int, temporaryName, targetName string, injectedRename func(int, string, int, string, uint) error) error {
	temporaryFD, err := openDirectoryAt(versionFD, temporaryName)
	if err != nil {
		return fmt.Errorf("cannot open temporary rootfs directory without following symlinks: %v", err)
	}
	defer unix.Close(temporaryFD)
	old, err := targetExistsAt(versionFD, targetName)
	if err != nil {
		return fmt.Errorf("cannot inspect existing rootfs target: %v", err)
	}
	rename := func(fromFD int, fromName string, toFD int, toName string, flags uint) error {
		if injectedRename != nil {
			return injectedRename(fromFD, fromName, toFD, toName, flags)
		}
		return unix.Renameat2(fromFD, fromName, toFD, toName, flags)
	}
	if !old {
		if err := rename(temporaryFD, "rootfs", versionFD, targetName, unix.RENAME_NOREPLACE); err != nil {
			return fmt.Errorf("cannot atomically publish rootfs: %v", err)
		}
		return nil
	}
	if err := rename(temporaryFD, "rootfs", versionFD, targetName, unix.RENAME_EXCHANGE); err != nil {
		return fmt.Errorf("cannot atomically replace rootfs: %v", err)
	}
	if err := removeManagedTreeAt(temporaryFD, "rootfs"); err != nil {
		return fmt.Errorf("cannot remove previous rootfs: %v", err)
	}
	return nil
}

func targetExistsAt(parentFD int, name string) (bool, error) {
	fd, err := unix.Openat(parentFD, name, unix.O_PATH|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err == unix.ENOENT {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, unix.Close(fd)
}
