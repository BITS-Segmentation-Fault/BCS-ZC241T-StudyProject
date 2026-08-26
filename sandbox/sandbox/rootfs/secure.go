//go:build linux

package rootfs

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

const secureResolve = unix.RESOLVE_BENEATH | unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_SYMLINKS

func openDirectoryPath(name string) (int, error) {
	if name == "" || !filepath.IsAbs(name) || hasParentComponent(name) {
		return -1, fmt.Errorf("path %q is not a safe absolute directory path", name)
	}
	how := &unix.OpenHow{
		Flags:   uint64(unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC | unix.O_NOFOLLOW),
		Resolve: unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_SYMLINKS,
	}
	return unix.Openat2(unix.AT_FDCWD, filepath.Clean(name), how)
}

func openDirectoryAt(parent int, name string) (int, error) {
	if name == "" || strings.ContainsRune(name, '/') || name == "." || name == ".." {
		return -1, fmt.Errorf("unsafe directory component %q", name)
	}
	how := &unix.OpenHow{
		Flags:   uint64(unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC | unix.O_NOFOLLOW),
		Resolve: secureResolve,
	}
	return unix.Openat2(parent, name, how)
}

func openCacheDirectory(cacheDir string) (int, error) {
	if cacheDir == "" || !filepath.IsAbs(cacheDir) {
		return -1, fmt.Errorf("cache directory %q is not an absolute path", cacheDir)
	}
	parts := strings.Split(filepath.ToSlash(cacheDir), "/")
	current, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return -1, fmt.Errorf("cannot open filesystem root: %v", err)
	}
	for _, part := range parts[1:] {
		if part == "" || part == "." {
			continue
		}
		if part == ".." {
			unix.Close(current)
			return -1, fmt.Errorf("cache directory %q contains ..", cacheDir)
		}
		next, openErr := openDirectoryAt(current, part)
		if openErr == unix.ENOENT {
			if mkdirErr := unix.Mkdirat(current, part, 0700); mkdirErr != nil && mkdirErr != unix.EEXIST {
				unix.Close(current)
				return -1, fmt.Errorf("cannot create cache directory component %q: %v", part, mkdirErr)
			}
			next, openErr = openDirectoryAt(current, part)
		}
		if openErr != nil {
			unix.Close(current)
			return -1, fmt.Errorf("cannot open cache directory component %q without following symlinks: %v", part, openErr)
		}
		unix.Close(current)
		current = next
	}
	if err := validateManagedDirectory(current, cacheDir); err != nil {
		unix.Close(current)
		return -1, err
	}
	return current, nil
}

func ensureManagedVersionDir(cacheDir string) (string, int, error) {
	cacheFD, err := openCacheDirectory(cacheDir)
	if err != nil {
		return "", -1, err
	}
	current := cacheFD
	currentPath := filepath.Clean(cacheDir)
	for _, component := range []string{"bcs-zc241t-sandbox", "rootfs", provider, version} {
		next, openErr := openDirectoryAt(current, component)
		if openErr == unix.ENOENT {
			if mkdirErr := unix.Mkdirat(current, component, 0700); mkdirErr != nil && mkdirErr != unix.EEXIST {
				unix.Close(current)
				return "", -1, fmt.Errorf("cannot create managed cache directory %q: %v", component, mkdirErr)
			}
			next, openErr = openDirectoryAt(current, component)
		}
		if openErr != nil {
			unix.Close(current)
			return "", -1, fmt.Errorf("cannot open managed cache directory %q without following symlinks: %v", component, openErr)
		}
		if err := validateManagedDirectory(next, filepath.Join(currentPath, component)); err != nil {
			unix.Close(next)
			unix.Close(current)
			return "", -1, err
		}
		unix.Close(current)
		current = next
		currentPath = filepath.Join(currentPath, component)
	}
	return currentPath, current, nil
}

func validateManagedDirectory(fd int, name string) error {
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return fmt.Errorf("cannot stat managed directory %q: %v", name, err)
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFDIR {
		return fmt.Errorf("managed directory %q is not a directory", name)
	}
	if uint32(os.Getuid()) != stat.Uid {
		return fmt.Errorf("managed directory %q is not owned by the invoking user", name)
	}
	if stat.Mode&0022 != 0 {
		return fmt.Errorf("managed directory %q is writable by group or other users", name)
	}
	return nil
}

func acquireLockAt(versionFD int) (*os.File, error) {
	fd, err := unix.Openat(versionFD, lockName, unix.O_RDWR|unix.O_CREAT|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, err
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		unix.Close(fd)
		return nil, err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Uid != uint32(os.Getuid()) || stat.Mode&0077 != 0 {
		unix.Close(fd)
		return nil, fmt.Errorf("managed cache lock has unsafe type, ownership, or mode")
	}
	if err := syscall.Flock(fd, syscall.LOCK_EX); err != nil {
		unix.Close(fd)
		return nil, err
	}
	return os.NewFile(uintptr(fd), lockName), nil
}

func syncDirectory(fd int, name string) error {
	if err := unix.Fsync(fd); err != nil {
		return fmt.Errorf("cannot fsync %s: %v", name, err)
	}
	return nil
}

func removeTreeAt(parentFD int, name string) error {
	entry, err := openEntryAt(parentFD, name)
	if err != nil {
		if err == unix.ENOENT {
			return nil
		}
		return err
	}
	defer unix.Close(entry.fd)
	if entry.stat.Mode&unix.S_IFMT == unix.S_IFDIR {
		names, err := readDirectoryNames(entry.fd)
		if err != nil {
			return err
		}
		for _, child := range names {
			if err := removeTreeAt(entry.fd, child); err != nil {
				return err
			}
		}
		return unix.Unlinkat(parentFD, name, unix.AT_REMOVEDIR)
	}
	return unix.Unlinkat(parentFD, name, 0)
}

func hasParentComponent(name string) bool {
	for _, part := range strings.Split(filepath.ToSlash(name), "/") {
		if part == ".." {
			return true
		}
	}
	return false
}
