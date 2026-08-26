//go:build linux

// Package rootfs provisions and verifies the sandbox's managed rootfs.
package rootfs

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

const (
	provider = "alpine"
	version  = "3.24.1"

	manifestName = "manifest.json"
	lockName     = ".lock"

	requestTimeout = 45 * time.Second
	connectTimeout = 10 * time.Second
)

// releaseInfo contains the reviewed metadata for one pinned Alpine archive.
// MaxArchiveBytes is both the compressed-response limit and the reviewed
// archive-size ceiling.
type releaseInfo struct {
	AlpineArch      string
	ArchiveName     string
	URL             string
	SHA256          string
	TreeSHA256      string
	MaxArchiveBytes int64
}

var releaseCatalog = map[string]releaseInfo{
	"amd64": {
		AlpineArch:      "x86_64",
		ArchiveName:     "alpine-minirootfs-3.24.1-x86_64.tar.gz",
		URL:             "https://dl-cdn.alpinelinux.org/alpine/v3.24/releases/x86_64/alpine-minirootfs-3.24.1-x86_64.tar.gz",
		SHA256:          "41f73e3cf5fa919b8aa5ca6b30dc48f0da2720776d7423e2a7748211456fe081",
		TreeSHA256:      "f35a4d7394df512b1727eebe935f54cc38a4b15154e56ad74722cb3683c4eb9f",
		MaxArchiveBytes: 3698422,
	},
	"arm64": {
		AlpineArch:      "aarch64",
		ArchiveName:     "alpine-minirootfs-3.24.1-aarch64.tar.gz",
		URL:             "https://dl-cdn.alpinelinux.org/alpine/v3.24/releases/aarch64/alpine-minirootfs-3.24.1-aarch64.tar.gz",
		SHA256:          "f55a90f69052c5bd6f92cb09a8f47065970830b194c917a006fb94028e721259",
		TreeSHA256:      "d685f267ee308d816da007134d44d1e661b4a69ca81ede67b19381eeb25dbb66",
		MaxArchiveBytes: 4023732,
	},
}

// Provisioner resolves explicit rootfs paths or provisions the managed
// Alpine rootfs in the user's cache. Client may be supplied by hermetic tests;
// the zero value uses the timeout- and redirect-checked default client.
type Provisioner struct {
	CacheDir string
	Client   *http.Client

	// releases is intentionally private: tests replace the catalog with small
	// synthetic archives, while production always uses releaseCatalog above.
	releases      map[string]releaseInfo
	makeTemp      func(string, string) (string, error)
	renamePath    func(string, string) error
	allowTestURLs bool
}

func releaseInfoFor(goArch string) (releaseInfo, error) {
	release, ok := releaseCatalog[goArch]
	if !ok {
		return releaseInfo{}, fmt.Errorf("unsupported sandbox architecture %q", goArch)
	}
	return release, nil
}

func cachePath(cacheDir, goArch string) (string, error) {
	release, err := releaseInfoFor(goArch)
	if err != nil {
		return "", err
	}
	if cacheDir == "" {
		return "", fmt.Errorf("cache directory cannot be empty")
	}
	return filepath.Join(cacheDir, "bcs-zc241t-sandbox", "rootfs", provider, version, release.AlpineArch), nil
}

// Resolve returns a validated explicit rootfs or the completed managed rootfs.
// Explicit paths never access the cache or network.
func (p Provisioner) Resolve(source string) (string, error) {
	if source != "" {
		return validateExplicitRootfs(source)
	}

	cacheDir := p.CacheDir
	if cacheDir == "" {
		var err error
		cacheDir, err = os.UserCacheDir()
		if err != nil {
			return "", fmt.Errorf("cannot determine user cache directory: %v", err)
		}
	}
	goArch := runtime.GOARCH
	release, ok := p.catalog()[goArch]
	if !ok {
		return "", fmt.Errorf("unsupported sandbox architecture %q", goArch)
	}
	target, err := cachePath(cacheDir, goArch)
	if err != nil {
		return "", err
	}
	return p.provision(cacheDir, target, release)
}

func validateExplicitRootfs(source string) (string, error) {
	fd, err := openDirectoryPath(source)
	if err != nil {
		return "", fmt.Errorf("configured rootfs_source %q is unavailable: %v", source, err)
	}
	defer unix.Close(fd)
	return source, nil
}

func (p Provisioner) catalog() map[string]releaseInfo {
	if p.releases != nil {
		return p.releases
	}
	return releaseCatalog
}

func (p Provisioner) provision(cacheDir, target string, release releaseInfo) (string, error) {
	versionDir, versionFD, err := ensureManagedVersionDir(cacheDir)
	if err != nil {
		return "", p.provisionError(release, target, err)
	}
	defer unix.Close(versionFD)
	target = filepath.Join(versionDir, release.AlpineArch)

	lock, err := acquireLockAt(versionFD)
	if err != nil {
		return "", p.provisionError(release, target, fmt.Errorf("cannot lock cache: %v", err))
	}
	defer lock.Close()

	targetName := release.AlpineArch
	if err := validatePublishedRootfsAt(versionFD, targetName, release); err == nil {
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
		_ = removeTreeAt(versionFD, temporaryName)
	}()

	archivePath := filepath.Join(temporary, release.ArchiveName)
	if err := p.download(context.Background(), release, archivePath); err != nil {
		return "", p.provisionError(release, target, err)
	}

	extracted := filepath.Join(temporary, "rootfs")
	if err := os.Mkdir(extracted, 0700); err != nil {
		return "", p.provisionError(release, target, fmt.Errorf("cannot create extraction directory: %v", err))
	}
	if err := extractArchive(archivePath, extracted, defaultExtractionLimits); err != nil {
		return "", p.provisionError(release, target, err)
	}
	if err := validateRootfsLayout(extracted); err != nil {
		return "", p.provisionError(release, target, err)
	}
	treeHash, err := treeDigest(extracted)
	if err != nil {
		return "", p.provisionError(release, target, fmt.Errorf("cannot hash extracted rootfs: %v", err))
	}
	if release.TreeSHA256 == "" || treeHash != release.TreeSHA256 {
		return "", p.provisionError(release, target, fmt.Errorf("extracted rootfs tree SHA-256 mismatch: got %s, want %s", treeHash, release.TreeSHA256))
	}
	if err := writeManifest(extracted, release); err != nil {
		return "", p.provisionError(release, target, err)
	}
	if err := syncDirectoryPath(extracted, "completed rootfs"); err != nil {
		return "", p.provisionError(release, target, err)
	}
	if err := publishReplacement(versionFD, versionDir, temporaryName, targetName, p.renamePath); err != nil {
		return "", p.provisionError(release, target, err)
	}
	if err := syncDirectory(versionFD, versionDir); err != nil {
		return "", p.provisionError(release, target, err)
	}
	return target, nil
}

func (p Provisioner) provisionError(release releaseInfo, target string, err error) error {
	return fmt.Errorf("managed Alpine rootfs provisioning failed from %s: %v; cache: %s; configure rootfs_source to use a custom rootfs", release.URL, err, target)
}

func (p Provisioner) download(ctx context.Context, release releaseInfo, destination string) error {
	origin, err := validateReleaseURL(release.URL, p.allowTestURLs)
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
		if clone.Timeout == 0 {
			clone.Timeout = requestTimeout
		}
		client = &clone
	}
	requestContext, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(requestContext, http.MethodGet, release.URL, nil)
	if err != nil {
		return fmt.Errorf("cannot create download request: %v", err)
	}
	response, err := client.Do(request)
	if err != nil {
		return fmt.Errorf("download request failed: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("download returned HTTP status %s", response.Status)
	}
	if response.ContentLength > release.MaxArchiveBytes {
		return fmt.Errorf("download exceeds the %d-byte archive limit", release.MaxArchiveBytes)
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
	limited := io.LimitReader(response.Body, release.MaxArchiveBytes+1)
	count, err := io.Copy(file, io.TeeReader(limited, hash))
	if err != nil {
		return fmt.Errorf("cannot save downloaded archive: %v", err)
	}
	if count > release.MaxArchiveBytes {
		return fmt.Errorf("download exceeds the %d-byte archive limit", release.MaxArchiveBytes)
	}
	if got := hex.EncodeToString(hash.Sum(nil)); got != release.SHA256 {
		return fmt.Errorf("archive SHA-256 mismatch: got %s, want %s", got, release.SHA256)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("cannot fsync downloaded archive: %v", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("cannot close downloaded archive: %v", err)
	}
	remove = false
	return nil
}

func defaultHTTPClient() *http.Client {
	return defaultHTTPClientFor(nil)
}

func defaultHTTPClientFor(origin *url.URL) *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.DialContext = (&net.Dialer{Timeout: connectTimeout}).DialContext
	return &http.Client{
		Transport:     transport,
		Timeout:       requestTimeout,
		CheckRedirect: redirectPolicy(nil),
	}
}

func validateReleaseURL(raw string, allowTestURL bool) (*url.URL, error) {
	parsed, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("invalid rootfs source URL: %v", err)
	}
	if parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, fmt.Errorf("rootfs source URL must be an HTTPS URL without userinfo, query, or fragment")
	}
	if !allowTestURL && !strings.EqualFold(parsed.Host, "dl-cdn.alpinelinux.org") {
		return nil, fmt.Errorf("rootfs source URL host %q is not the pinned Alpine host", parsed.Host)
	}
	if parsed.Path == "" || filepath.Base(parsed.Path) == "." || strings.Contains(parsed.Path, "..") {
		return nil, fmt.Errorf("rootfs source URL has an unsafe release path")
	}
	return parsed, nil
}

func redirectPolicy(origin *url.URL) func(*http.Request, []*http.Request) error {
	return func(request *http.Request, previous []*http.Request) error {
		if len(previous) >= 3 {
			return fmt.Errorf("refusing redirect after %d hops", len(previous))
		}
		if request.URL.Scheme != "https" || request.URL.User != nil {
			return fmt.Errorf("refusing redirect to a non-HTTPS or userinfo URL %s", request.URL)
		}
		if origin != nil && !strings.EqualFold(request.URL.Host, origin.Host) {
			return fmt.Errorf("refusing redirect to a different host %q", request.URL.Host)
		}
		return nil
	}
}

type manifest struct {
	Provider     string `json:"provider"`
	Version      string `json:"version"`
	Architecture string `json:"architecture"`
	Archive      string `json:"archive"`
	SHA256       string `json:"sha256"`
	TreeSHA256   string `json:"tree_sha256"`
}

func manifestFor(release releaseInfo) manifest {
	return manifest{
		Provider:     provider,
		Version:      version,
		Architecture: release.AlpineArch,
		Archive:      release.ArchiveName,
		SHA256:       release.SHA256,
		TreeSHA256:   release.TreeSHA256,
	}
}

func writeManifest(root string, release releaseInfo) error {
	data, err := json.MarshalIndent(manifestFor(release), "", "  ")
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

func validatePublishedRootfs(root string, release releaseInfo) error {
	rootFD, err := openDirectoryPath(root)
	if err != nil {
		return err
	}
	defer unix.Close(rootFD)
	return validatePublishedRootfsFD(rootFD, release)
}

func validatePublishedRootfsAt(versionFD int, targetName string, release releaseInfo) error {
	rootFD, err := openDirectoryAt(versionFD, targetName)
	if err != nil {
		return err
	}
	defer unix.Close(rootFD)
	return validatePublishedRootfsFD(rootFD, release)
}

func validatePublishedRootfsFD(rootFD int, release releaseInfo) error {
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
	data, err := io.ReadAll(file)
	closeErr := file.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
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
	if got != manifestFor(release) {
		return fmt.Errorf("rootfs manifest does not match pinned release")
	}
	if err := validateRootfsLayoutFD(rootFD); err != nil {
		return err
	}
	gotTree, err := treeDigestFD(rootFD)
	if err != nil {
		return fmt.Errorf("cannot verify published rootfs tree: %v", err)
	}
	if release.TreeSHA256 == "" || gotTree != release.TreeSHA256 {
		return fmt.Errorf("published rootfs tree SHA-256 mismatch: got %s, want %s", gotTree, release.TreeSHA256)
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

func publishReplacement(versionFD int, versionPath, temporaryName, targetName string, injectedRename func(string, string) error) error {
	temporaryFD, err := openDirectoryAt(versionFD, temporaryName)
	if err != nil {
		return fmt.Errorf("cannot open temporary rootfs directory without following symlinks: %v", err)
	}
	defer unix.Close(temporaryFD)
	old, err := targetExistsAt(versionFD, targetName)
	if err != nil {
		return fmt.Errorf("cannot inspect existing rootfs target: %v", err)
	}
	rename := func(fromFD int, fromName string, toFD int, toName string, oldPath, newPath string) error {
		if injectedRename != nil {
			return injectedRename(oldPath, newPath)
		}
		return unix.Renameat(fromFD, fromName, toFD, toName)
	}
	sourceName := filepath.Join(temporaryName, "rootfs")
	if !old {
		if err := rename(temporaryFD, "rootfs", versionFD, targetName, filepath.Join(versionPath, sourceName), filepath.Join(versionPath, targetName)); err != nil {
			return fmt.Errorf("cannot atomically publish rootfs: %v", err)
		}
		return nil
	}

	var backupName string
	for attempt := 0; attempt < 8; attempt++ {
		backupName = fmt.Sprintf(".rootfs-backup-%d-%d", os.Getpid(), time.Now().UnixNano()+int64(attempt))
		err = rename(versionFD, targetName, versionFD, backupName, filepath.Join(versionPath, targetName), filepath.Join(versionPath, backupName))
		if err != unix.EEXIST {
			break
		}
	}
	if err != nil {
		return fmt.Errorf("cannot move existing rootfs to a private backup: %v", err)
	}
	if err := rename(temporaryFD, "rootfs", versionFD, targetName, filepath.Join(versionPath, sourceName), filepath.Join(versionPath, targetName)); err != nil {
		restoreErr := rename(versionFD, backupName, versionFD, targetName, filepath.Join(versionPath, backupName), filepath.Join(versionPath, targetName))
		if restoreErr != nil {
			return fmt.Errorf("cannot publish replacement rootfs: %v; cannot restore previous rootfs: %v", err, restoreErr)
		}
		return fmt.Errorf("cannot publish replacement rootfs: %v", err)
	}
	if err := removeTreeAt(versionFD, backupName); err != nil {
		return fmt.Errorf("replacement rootfs was published but old backup cleanup failed: %v", err)
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
