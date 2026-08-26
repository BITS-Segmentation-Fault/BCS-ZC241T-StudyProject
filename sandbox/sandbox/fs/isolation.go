//go:build linux

// Package fs contains the mount and root-transition operations used by the
// sandbox. All user-selected filesystem objects are held by descriptors before
// any mount is attached, so pathname replacement cannot redirect a mount.
package fs

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"sandbox/sandbox/config"

	"golang.org/x/sys/unix"
)

const secureResolve = unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_SYMLINKS
const beneathResolve = unix.RESOLVE_BENEATH | secureResolve
const emptyPathMountFlags = unix.MOVE_MOUNT_F_EMPTY_PATH

// IsolateRootFS creates and enters the isolated root. It intentionally uses
// only the new mount API after the initial openat2 lookups: older kernels are
// rejected instead of receiving a race-prone path-based fallback.
func IsolateRootFS(rootfsPath string, bindMounts []config.BindMount, readOnlyRoot bool, dnsServers []string) error {
	if err := validateIsolationPath("rootfs", rootfsPath); err != nil {
		return err
	}

	rootFD, err := openSecure(unix.AT_FDCWD, rootfsPath, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("pre-flight error: target rootfs path %q does not exist: %w", rootfsPath, err)
		}
		return fmt.Errorf("pre-flight error: cannot open rootfs %q without symlinks: %w", rootfsPath, err)
	}
	defer unix.Close(rootFD)

	type heldBind struct {
		mount  config.BindMount
		source int
		target int
		isDir  bool
	}
	holds := make([]heldBind, 0, len(bindMounts))
	closeHeld := func() {
		for _, held := range holds {
			_ = unix.Close(held.source)
			if held.target >= 0 {
				_ = unix.Close(held.target)
			}
		}
	}
	defer closeHeld()

	for _, bind := range bindMounts {
		if err := validateIsolationPath("bind target", bind.ContainerPath); err != nil {
			return err
		}
		if filepath.Clean(bind.ContainerPath) == "/" {
			return fmt.Errorf("value_error: bind target %q cannot be root", bind.ContainerPath)
		}
		source, isDir, openErr := openBindSource(bind.HostPath)
		if openErr != nil {
			return openErr
		}
		holds = append(holds, heldBind{mount: bind, source: source, target: -1, isDir: isDir})
	}

	if err := unix.Mount("", "/", "", unix.MS_PRIVATE|unix.MS_REC, ""); err != nil {
		return fmt.Errorf("failed to make root mount space private: %w", err)
	}

	rootMount, err := cloneMount(rootFD, true)
	if err != nil {
		return fmt.Errorf("clone rootfs mount: %w", err)
	}
	defer unix.Close(rootMount)
	rootAttrs := unix.MountAttr{Attr_set: unix.MOUNT_ATTR_NOSUID | unix.MOUNT_ATTR_NODEV}
	if readOnlyRoot {
		rootAttrs.Attr_set |= unix.MOUNT_ATTR_RDONLY
	}
	if err := setRecursiveMountAttrs(rootMount, rootAttrs); err != nil {
		return fmt.Errorf("configure rootfs mount: %w", err)
	}
	if err := moveMount(rootMount, rootFD); err != nil {
		return fmt.Errorf("attach rootfs mount: %w", err)
	}

	for i := range holds {
		target, targetErr := openTarget(rootMount, holds[i].mount.ContainerPath)
		if targetErr != nil {
			return fmt.Errorf("pre-flight error: cannot open bind target %q: %w", holds[i].mount.ContainerPath, targetErr)
		}
		holds[i].target = target
		if err := requireSameType(holds[i].source, target, holds[i].mount.HostPath, holds[i].mount.ContainerPath); err != nil {
			return err
		}
	}
	procTarget, err := openTarget(rootMount, "/proc")
	if err != nil {
		return fmt.Errorf("pre-flight error: cannot open proc target: %w", err)
	}
	defer unix.Close(procTarget)
	if err := requireDirectory(procTarget, "/proc"); err != nil {
		return err
	}

	var dnsTarget int
	if len(dnsServers) > 0 {
		dnsTarget, err = openTarget(rootMount, "/etc/resolv.conf")
		if err != nil {
			return fmt.Errorf("pre-flight error: cannot open DNS target: %w", err)
		}
		defer unix.Close(dnsTarget)
		if err := requireRegularFile(dnsTarget, "/etc/resolv.conf"); err != nil {
			return err
		}
	}

	for _, held := range holds {
		if err := attachBindMount(rootMount, held.target, held.mount, held.source, held.isDir); err != nil {
			return fmt.Errorf("attach bind mount %q: %w", held.mount.ContainerPath, err)
		}
	}

	procMount, err := mountProc()
	if err != nil {
		return fmt.Errorf("create sandbox proc mount: %w", err)
	}
	defer unix.Close(procMount)
	if err := setRecursiveMountAttrs(procMount, unix.MountAttr{Attr_set: unix.MOUNT_ATTR_NOSUID | unix.MOUNT_ATTR_NODEV | unix.MOUNT_ATTR_NOEXEC}); err != nil {
		return fmt.Errorf("configure sandbox proc mount: %w", err)
	}
	if err := attachMount(rootMount, procTarget, procMount, "/proc", -1, unix.PROC_SUPER_MAGIC); err != nil {
		return fmt.Errorf("attach sandbox proc mount: %w", err)
	}

	if len(dnsServers) > 0 {
		dnsMount, dnsSource, err := mountDNS(dnsServers)
		if err != nil {
			return fmt.Errorf("create DNS mount: %w", err)
		}
		defer unix.Close(dnsMount)
		defer unix.Close(dnsSource)
		if err := setRecursiveMountAttrs(dnsMount, unix.MountAttr{Attr_set: unix.MOUNT_ATTR_RDONLY | unix.MOUNT_ATTR_NOSUID | unix.MOUNT_ATTR_NODEV | unix.MOUNT_ATTR_NOEXEC}); err != nil {
			return fmt.Errorf("configure DNS mount: %w", err)
		}
		if err := attachMount(rootMount, dnsTarget, dnsMount, "/etc/resolv.conf", dnsSource, 0); err != nil {
			return fmt.Errorf("attach DNS mount: %w", err)
		}
	}

	if err := unix.Fchdir(rootMount); err != nil {
		return fmt.Errorf("enter new root mount: %w", err)
	}
	if err := unix.PivotRoot(".", "."); err != nil {
		return fmt.Errorf("pivot_root: %w", err)
	}
	if err := unix.Unmount(".", unix.MNT_DETACH); err != nil {
		return fmt.Errorf("detach old host root: %w", err)
	}
	if err := unix.Chdir("/"); err != nil {
		return fmt.Errorf("enter isolated root: %w", err)
	}
	return nil
}

func openSecure(dirfd int, path string, flags int, mode uint32) (int, error) {
	how := &unix.OpenHow{Flags: uint64(flags), Mode: uint64(mode), Resolve: secureResolve}
	return unix.Openat2(dirfd, path, how)
}

func openBindSource(path string) (int, bool, error) {
	if err := validateIsolationPath("bind source", path); err != nil {
		return -1, false, err
	}
	fd, err := openSecure(unix.AT_FDCWD, path, unix.O_PATH|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, false, fmt.Errorf("pre-flight error: cannot open bind source %q: %w", path, err)
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		_ = unix.Close(fd)
		return -1, false, fmt.Errorf("pre-flight error: cannot stat bind source %q: %w", path, err)
	}
	sourceType := stat.Mode & unix.S_IFMT
	if sourceType != unix.S_IFDIR && sourceType != unix.S_IFREG {
		_ = unix.Close(fd)
		return -1, false, fmt.Errorf("pre-flight error: bind source %q must be a regular file or directory", path)
	}
	return fd, sourceType == unix.S_IFDIR, nil
}

func openTarget(rootFD int, path string) (int, error) {
	if err := validateIsolationPath("target", path); err != nil {
		return -1, err
	}
	clean := filepath.Clean(path)
	if clean == "/" {
		return -1, fmt.Errorf("target path %q is not a safe root-relative path", path)
	}
	relative := strings.TrimPrefix(clean, "/")
	how := &unix.OpenHow{Flags: unix.O_PATH | unix.O_CLOEXEC, Resolve: beneathResolve}
	fd, err := unix.Openat2(rootFD, relative, how)
	if err != nil {
		return -1, err
	}
	return fd, nil
}

func attachBindMount(rootMount, target int, bind config.BindMount, source int, isDir bool) error {
	mountFD, err := cloneMount(source, isDir)
	if err != nil {
		return fmt.Errorf("clone bind source %q: %w", bind.HostPath, err)
	}
	defer unix.Close(mountFD)
	attrs := unix.MountAttr{Attr_set: unix.MOUNT_ATTR_NOSUID | unix.MOUNT_ATTR_NODEV}
	if !bind.Writable {
		attrs.Attr_set |= unix.MOUNT_ATTR_RDONLY
	}
	if err := setRecursiveMountAttrs(mountFD, attrs); err != nil {
		return err
	}
	return attachMount(rootMount, target, mountFD, bind.ContainerPath, source, 0)
}

func attachMount(rootMount, target, mountFD int, targetPath string, expectedFD int, expectedFSType int64) error {
	if err := moveMount(mountFD, target); err != nil {
		return err
	}
	attached, err := openTarget(rootMount, targetPath)
	if err != nil {
		return fmt.Errorf("reopen attached target %q: %w", targetPath, err)
	}
	defer unix.Close(attached)
	if expectedFD >= 0 {
		if err := requireSameObject(expectedFD, attached, targetPath); err != nil {
			return err
		}
	}
	if expectedFSType != 0 {
		var stat unix.Statfs_t
		if err := unix.Fstatfs(attached, &stat); err != nil {
			return fmt.Errorf("stat attached target %q: %w", targetPath, err)
		}
		if stat.Type != expectedFSType {
			return fmt.Errorf("attached target %q has filesystem type %#x, want %#x", targetPath, stat.Type, expectedFSType)
		}
	}
	return nil
}

func requireSameObject(expected, actual int, targetPath string) error {
	var expectedStat, actualStat unix.Stat_t
	if err := unix.Fstat(expected, &expectedStat); err != nil {
		return fmt.Errorf("stat expected mount source for %q: %w", targetPath, err)
	}
	if err := unix.Fstat(actual, &actualStat); err != nil {
		return fmt.Errorf("stat attached target %q: %w", targetPath, err)
	}
	if expectedStat.Dev != actualStat.Dev || expectedStat.Ino != actualStat.Ino {
		return fmt.Errorf("attached target %q does not resolve to its mounted source", targetPath)
	}
	return nil
}

func requireSameType(source, target int, sourceName, targetName string) error {
	var sourceStat, targetStat unix.Stat_t
	if err := unix.Fstat(source, &sourceStat); err != nil {
		return fmt.Errorf("stat bind source %q: %w", sourceName, err)
	}
	if err := unix.Fstat(target, &targetStat); err != nil {
		return fmt.Errorf("stat bind target %q: %w", targetName, err)
	}
	sourceType := sourceStat.Mode & unix.S_IFMT
	targetType := targetStat.Mode & unix.S_IFMT
	if sourceType != targetType {
		return fmt.Errorf("pre-flight error: bind target %q type does not match source %q", targetName, sourceName)
	}
	if sourceType != unix.S_IFDIR && sourceType != unix.S_IFREG {
		return fmt.Errorf("pre-flight error: bind source %q must be a regular file or directory", sourceName)
	}
	return nil
}

func requireDirectory(fd int, name string) error {
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return fmt.Errorf("stat target %q: %w", name, err)
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFDIR {
		return fmt.Errorf("pre-flight error: target %q must be a directory", name)
	}
	return nil
}

func requireRegularFile(fd int, name string) error {
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return fmt.Errorf("stat target %q: %w", name, err)
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG {
		return fmt.Errorf("pre-flight error: target %q must be a regular file", name)
	}
	return nil
}

func cloneMount(fd int, recursive bool) (int, error) {
	flags := uint(unix.OPEN_TREE_CLONE | unix.OPEN_TREE_CLOEXEC | unix.AT_EMPTY_PATH)
	if recursive {
		flags |= unix.AT_RECURSIVE
	}
	mountFD, err := unix.OpenTree(fd, "", flags)
	if err != nil {
		return -1, fmt.Errorf("mount API open_tree unavailable or failed: %w", err)
	}
	return mountFD, nil
}

func setRecursiveMountAttrs(fd int, attrs unix.MountAttr) error {
	if err := unix.MountSetattr(fd, "", unix.AT_EMPTY_PATH|unix.AT_RECURSIVE, &attrs); err != nil {
		return fmt.Errorf("mount API mount_setattr failed: %w", err)
	}
	return nil
}

func moveMount(source, target int) error {
	if err := unix.MoveMount(source, "", target, "", emptyPathMountFlags|unix.MOVE_MOUNT_T_EMPTY_PATH); err != nil {
		return err
	}
	return nil
}

func mountProc() (int, error) {
	context, err := unix.Fsopen("proc", unix.FSOPEN_CLOEXEC)
	if err != nil {
		return -1, fmt.Errorf("mount API fsopen proc: %w", err)
	}
	defer unix.Close(context)
	if err := unix.FsconfigCreate(context); err != nil {
		return -1, fmt.Errorf("mount API fsconfig proc: %w", err)
	}
	mountFD, err := unix.Fsmount(context, unix.FSMOUNT_CLOEXEC, 0)
	if err != nil {
		return -1, fmt.Errorf("mount API fsmount proc: %w", err)
	}
	return mountFD, nil
}

func mountDNS(servers []string) (int, int, error) {
	fd, err := makeDNSMemfd(servers)
	if err != nil {
		return -1, -1, err
	}
	mountFD, err := cloneMount(fd, false)
	if err != nil {
		_ = unix.Close(fd)
		return -1, -1, err
	}
	return mountFD, fd, nil
}

func makeDNSMemfd(servers []string) (int, error) {
	fd, err := unix.MemfdCreate("sandbox-resolv.conf", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
	if err != nil {
		return -1, fmt.Errorf("create DNS memfd: %w", err)
	}
	closeFD := true
	defer func() {
		if closeFD {
			_ = unix.Close(fd)
		}
	}()
	var content strings.Builder
	for _, server := range servers {
		content.WriteString("nameserver ")
		content.WriteString(server)
		content.WriteByte('\n')
	}
	data := []byte(content.String())
	for len(data) > 0 {
		n, writeErr := unix.Write(fd, data)
		if writeErr != nil {
			return -1, fmt.Errorf("write DNS memfd: %w", writeErr)
		}
		if n == 0 {
			return -1, fmt.Errorf("write DNS memfd: %w", unix.Errno(unix.EIO))
		}
		data = data[n:]
	}
	if _, err := unix.FcntlInt(uintptr(fd), unix.F_ADD_SEALS, unix.F_SEAL_SEAL|unix.F_SEAL_SHRINK|unix.F_SEAL_GROW|unix.F_SEAL_WRITE); err != nil {
		return -1, fmt.Errorf("seal DNS memfd: %w", err)
	}
	closeFD = false
	return fd, nil
}

func hasParentComponent(path string) bool {
	for _, part := range strings.Split(path, string(filepath.Separator)) {
		if part == ".." {
			return true
		}
	}
	return false
}

func validateIsolationPath(name, path string) error {
	if path == "" || strings.IndexByte(path, 0) >= 0 || !filepath.IsAbs(path) || hasParentComponent(path) {
		return fmt.Errorf("value_error: %s %q is not a safe path", name, path)
	}
	return nil
}
