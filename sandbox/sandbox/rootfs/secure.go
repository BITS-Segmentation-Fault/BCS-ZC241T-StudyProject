//go:build linux

package rootfs

import (
	"errors"
	"fmt"
	"io"
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

func ensureManagedVersionDir(cacheDir string, source managedSource) (string, int, error) {
	cacheFD, err := openCacheDirectory(cacheDir)
	if err != nil {
		return "", -1, err
	}
	current := cacheFD
	currentPath := filepath.Clean(cacheDir)
	for _, component := range []string{"bcs-zc241t-sandbox", "rootfs", source.Provider, source.Version} {
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
	return removeTreeAtInternal(parentFD, name, false)
}

// removeManagedTreeAt is used only after the managed cache hierarchy has been
// opened and ownership-checked. That permits the compatibility fallback for
// kernels without fchmodat2 while keeping arbitrary callers descriptor-only.
func removeManagedTreeAt(parentFD int, name string) error {
	return removeTreeAtInternal(parentFD, name, true)
}

type cleanupEntry struct {
	fd   int
	stat unix.Stat_t
}

func openCleanupEntry(parentFD int, name string) (cleanupEntry, error) {
	fd, err := unix.Openat(parentFD, name, unix.O_PATH|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return cleanupEntry{}, err
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		_ = unix.Close(fd)
		return cleanupEntry{}, err
	}
	return cleanupEntry{fd: fd, stat: stat}, nil
}

func removeTreeAtInternal(parentFD int, name string, allowPathFallback bool) error {
	entry, err := openCleanupEntry(parentFD, name)
	if err != nil {
		if err == unix.ENOENT {
			return nil
		}
		return err
	}
	if entry.stat.Mode&unix.S_IFMT == unix.S_IFDIR {
		defer unix.Close(entry.fd)
		if entry.stat.Uid != uint32(os.Getuid()) {
			return fmt.Errorf("cannot remove directory %q owned by another user", name)
		}
		if entry.stat.Mode&0700 != 0700 {
			if err := makeCleanupDirectoryTraversable(parentFD, name, entry, allowPathFallback); err != nil {
				return err
			}
		}
		readFD, err := openCleanupDirectory(entry)
		if err != nil {
			return err
		}
		readDirectory := os.NewFile(uintptr(readFD), "rootfs-cleanup-directory")
		if readDirectory == nil {
			_ = unix.Close(readFD)
			return fmt.Errorf("cannot open rootfs cleanup directory")
		}
		defer readDirectory.Close()
		for {
			names, readErr := readDirectoryBatch(readDirectory)
			if readErr != nil {
				return readErr
			}
			if len(names) == 0 {
				if err := unix.Unlinkat(parentFD, name, unix.AT_REMOVEDIR); err != nil {
					return err
				}
				return nil
			}
			var removeErr error
			for _, child := range names {
				removeErr = errors.Join(removeErr, removeTreeAtInternal(readFD, child, allowPathFallback))
			}
			if removeErr != nil {
				return removeErr
			}
		}
	}
	defer unix.Close(entry.fd)
	return unix.Unlinkat(parentFD, name, 0)
}

func openCleanupDirectory(entry cleanupEntry) (int, error) {
	readFD, err := unix.Openat(entry.fd, ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return -1, err
	}
	var stat unix.Stat_t
	if err := unix.Fstat(readFD, &stat); err != nil {
		_ = unix.Close(readFD)
		return -1, err
	}
	if stat.Dev != entry.stat.Dev || stat.Ino != entry.stat.Ino ||
		stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Uid != entry.stat.Uid {
		_ = unix.Close(readFD)
		return -1, fmt.Errorf("directory changed while being opened for cleanup")
	}
	return readFD, nil
}

func makeCleanupDirectoryTraversable(parentFD int, name string, entry cleanupEntry, allowPathFallback bool) error {
	mode := uint32(entry.stat.Mode & 07777)
	mode |= 0700
	if err := unix.Fchmodat(entry.fd, "", mode, unix.AT_EMPTY_PATH); err == nil {
		return nil
	} else if !isFchmodatUnavailable(err) {
		return fmt.Errorf("cannot make directory %q traversable by descriptor: %w", name, err)
	} else if !allowPathFallback {
		return fmt.Errorf("cannot make directory %q traversable: descriptor-bound fchmodat2 unavailable", name)
	}
	if err := unix.Fchmodat(parentFD, name, mode, 0); err != nil {
		return fmt.Errorf("cannot make directory %q traversable by parent-relative fallback: %w", name, err)
	}
	reopened, err := openCleanupEntry(parentFD, name)
	if err != nil {
		return fmt.Errorf("cannot verify directory %q after parent-relative chmod: %w", name, err)
	}
	defer unix.Close(reopened.fd)
	if reopened.stat.Dev != entry.stat.Dev || reopened.stat.Ino != entry.stat.Ino ||
		reopened.stat.Mode&unix.S_IFMT != unix.S_IFDIR || reopened.stat.Uid != entry.stat.Uid {
		return fmt.Errorf("directory %q changed during parent-relative chmod", name)
	}
	return nil
}

func isFchmodatUnavailable(err error) bool {
	return errors.Is(err, unix.ENOSYS) || errors.Is(err, unix.EOPNOTSUPP) || errors.Is(err, unix.ENOTSUP)
}

const cleanupDirectoryBatch = 64

func readDirectoryBatch(directory *os.File) ([]string, error) {
	entries, err := directory.ReadDir(cleanupDirectoryBatch)
	if err != nil && err != io.EOF {
		return nil, err
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	return names, nil
}

func hasParentComponent(name string) bool {
	for _, part := range strings.Split(filepath.ToSlash(name), "/") {
		if part == ".." {
			return true
		}
	}
	return false
}
