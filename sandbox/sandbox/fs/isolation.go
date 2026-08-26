//go:build linux

package fs

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"sandbox/sandbox/config"

	"golang.org/x/sys/unix"
)

const secureResolve = unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_SYMLINKS

// IsolateRootFS validates every configured path with openat2 before mounting.
// The kernel performs the no-symlink/no-magic-link walk, so a path cannot be
// redirected outside the rootfs by a symlink race or a .. component.
func IsolateRootFS(rootfsPath string, bindMounts []config.BindMount) (err error) {
	if rootfsPath == "" || !filepath.IsAbs(rootfsPath) {
		return fmt.Errorf("value_error: isolated rootfs path must be absolute")
	}
	if hasParentComponent(rootfsPath) {
		return fmt.Errorf("value_error: rootfs path %q contains ..", rootfsPath)
	}

	rootFD, err := openSecure(unix.AT_FDCWD, rootfsPath, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0, false)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("pre-flight error: target rootfs path %q does not exist", rootfsPath)
		}
		return fmt.Errorf("pre-flight error: cannot open rootfs %q without symlinks: %v", rootfsPath, err)
	}
	defer unix.Close(rootFD)

	// Validate and hold all host sources before changing mount state.
	type bindSource struct {
		config.BindMount
		fd int
	}
	sources := make([]bindSource, 0, len(bindMounts))
	for _, bindMount := range bindMounts {
		if !filepath.IsAbs(bindMount.HostPath) || hasParentComponent(bindMount.HostPath) {
			return fmt.Errorf("value_error: bind source %q must be an absolute, symlink-free path", bindMount.HostPath)
		}
		if !filepath.IsAbs(bindMount.ContainerPath) || bindMount.ContainerPath == "/" || hasParentComponent(bindMount.ContainerPath) {
			return fmt.Errorf("value_error: bind target %q must stay beneath the rootfs", bindMount.ContainerPath)
		}
		fd, openErr := openSecure(unix.AT_FDCWD, bindMount.HostPath, unix.O_PATH|unix.O_CLOEXEC, 0, false)
		if openErr != nil {
			return fmt.Errorf("pre-flight error: cannot open bind source %q: %v", bindMount.HostPath, openErr)
		}
		var stat unix.Stat_t
		if statErr := unix.Fstat(fd, &stat); statErr != nil {
			unix.Close(fd)
			return fmt.Errorf("pre-flight error: cannot stat bind source %q: %v", bindMount.HostPath, statErr)
		}
		if stat.Mode&unix.S_IFMT != unix.S_IFDIR && stat.Mode&unix.S_IFMT != unix.S_IFREG {
			unix.Close(fd)
			return fmt.Errorf("pre-flight error: bind source %q must be a regular file or directory", bindMount.HostPath)
		}
		sources = append(sources, bindSource{BindMount: bindMount, fd: fd})
	}
	defer func() {
		for _, source := range sources {
			_ = unix.Close(source.fd)
		}
	}()

	mounted := make([]string, 0, len(sources)+2)
	rollback := func() {
		for i := len(mounted) - 1; i >= 0; i-- {
			_ = syscall.Unmount(mounted[i], syscall.MNT_DETACH)
		}
	}
	committed := false
	defer func() {
		if !committed && err != nil {
			rollback()
		}
	}()

	if err = syscall.Mount("", "/", "", syscall.MS_PRIVATE|syscall.MS_REC, ""); err != nil {
		return fmt.Errorf("failed to make root mount space private: %v", err)
	}
	if err = syscall.Mount(rootfsPath, rootfsPath, "", syscall.MS_BIND|syscall.MS_REC, ""); err != nil {
		return fmt.Errorf("failed to bind-mount target rootfs path %q: %v", rootfsPath, err)
	}
	mounted = append(mounted, rootfsPath)

	for _, source := range sources {
		target := filepath.Join(rootfsPath, strings.TrimPrefix(source.ContainerPath, "/"))
		if err = ensureBindTarget(rootFD, source.ContainerPath, source.fd); err != nil {
			return err
		}
		if err = syscall.Mount(source.HostPath, target, "", syscall.MS_BIND|syscall.MS_REC, ""); err != nil {
			return fmt.Errorf("failed to bind mount %q to %q: %v", source.HostPath, source.ContainerPath, err)
		}
		mounted = append(mounted, target)
		if !source.Writable {
			if err = syscall.Mount("", target, "", syscall.MS_BIND|syscall.MS_REMOUNT|syscall.MS_RDONLY|syscall.MS_REC, ""); err != nil {
				return fmt.Errorf("failed to remount bind target %q read-only: %v", source.ContainerPath, err)
			}
		}
	}

	procPath := filepath.Join(rootfsPath, "proc")
	if err = ensureDirectory(rootFD, "/proc"); err != nil {
		return fmt.Errorf("failed to prepare /proc: %v", err)
	}
	if err = syscall.Mount("proc", procPath, "proc", syscall.MS_NOSUID|syscall.MS_NODEV|syscall.MS_NOEXEC, ""); err != nil {
		return fmt.Errorf("failed to mount sandbox proc filesystem: %v", err)
	}
	mounted = append(mounted, procPath)

	oldRootPath := filepath.Join(rootfsPath, ".old_host_root")
	if err = ensureDirectory(rootFD, "/.old_host_root"); err != nil {
		return fmt.Errorf("failed to prepare old root mount path: %v", err)
	}
	if err = syscall.PivotRoot(rootfsPath, oldRootPath); err != nil {
		return fmt.Errorf("pivot_root failed: %v", err)
	}
	if err = syscall.Chdir("/"); err != nil {
		return fmt.Errorf("failed to enter new root: %v", err)
	}
	if err = syscall.Unmount("/.old_host_root", syscall.MNT_DETACH); err != nil {
		return fmt.Errorf("failed to detach old host root: %v", err)
	}
	_ = os.Remove("/.old_host_root")
	committed = true
	return nil
}

func openSecure(dirfd int, path string, flags int, mode uint32, beneath bool) (int, error) {
	resolve := uint64(secureResolve)
	if beneath {
		resolve |= unix.RESOLVE_BENEATH
	}
	how := &unix.OpenHow{Flags: uint64(flags), Mode: uint64(mode), Resolve: resolve}
	return unix.Openat2(dirfd, path, how)
}

func ensureDirectory(rootFD int, path string) error {
	return ensurePath(rootFD, path, true)
}

func ensureBindTarget(rootFD int, path string, sourceFD int) error {
	var source unix.Stat_t
	if err := unix.Fstat(sourceFD, &source); err != nil {
		return fmt.Errorf("cannot stat bind source: %v", err)
	}
	isDir := source.Mode&unix.S_IFMT == unix.S_IFDIR
	return ensurePath(rootFD, path, isDir)
}

func ensurePath(rootFD int, path string, directory bool) error {
	clean := strings.TrimPrefix(filepath.Clean(path), "/")
	parts := strings.Split(clean, string(filepath.Separator))
	parent := rootFD
	opened := make([]int, 0, len(parts))
	defer func() {
		for _, fd := range opened {
			_ = unix.Close(fd)
		}
	}()
	for index, part := range parts {
		last := index == len(parts)-1
		fd, err := openSecure(parent, part, unix.O_PATH|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0, true)
		if err != nil && err != unix.ENOENT {
			return fmt.Errorf("unsafe path component %q: %v", part, err)
		}
		if err == unix.ENOENT {
			if !last || directory {
				if err := unix.Mkdirat(parent, part, 0755); err != nil && err != unix.EEXIST {
					return fmt.Errorf("create path component %q: %v", part, err)
				}
			} else {
				fd, err = unix.Openat(parent, part, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0644)
				if err != nil {
					return fmt.Errorf("create bind target %q: %v", path, err)
				}
				_ = unix.Close(fd)
				return nil
			}
			fd, err = openSecure(parent, part, unix.O_PATH|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0, true)
			if err != nil {
				return fmt.Errorf("reopen path component %q: %v", part, err)
			}
		}
		var stat unix.Stat_t
		if err := unix.Fstat(fd, &stat); err != nil {
			_ = unix.Close(fd)
			return err
		}
		actualDir := stat.Mode&unix.S_IFMT == unix.S_IFDIR
		if !last && !actualDir {
			_ = unix.Close(fd)
			return fmt.Errorf("path component %q is not a directory", part)
		}
		if last && actualDir != directory {
			_ = unix.Close(fd)
			return fmt.Errorf("bind target %q has the wrong type", path)
		}
		if !last {
			opened = append(opened, fd)
			parent = fd
		} else {
			_ = unix.Close(fd)
		}
	}
	return nil
}

func ChdirNoSymlinks(path string) error {
	if path == "" || !filepath.IsAbs(path) || hasParentComponent(path) {
		return fmt.Errorf("working directory %q is not a safe absolute path", path)
	}
	fd, err := openSecure(unix.AT_FDCWD, path, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0, false)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	return unix.Fchdir(fd)
}

func WriteTextNoSymlinks(path, data string) error {
	if path == "" || !filepath.IsAbs(path) || hasParentComponent(path) {
		return fmt.Errorf("file path %q is not safe", path)
	}
	fd, err := openSecure(unix.AT_FDCWD, path, unix.O_WRONLY|unix.O_CREAT|unix.O_TRUNC|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0644, false)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	if _, err := unix.Write(fd, []byte(data)); err != nil {
		return err
	}
	return nil
}

func hasParentComponent(path string) bool {
	for _, part := range strings.Split(path, string(filepath.Separator)) {
		if part == ".." {
			return true
		}
	}
	return false
}
