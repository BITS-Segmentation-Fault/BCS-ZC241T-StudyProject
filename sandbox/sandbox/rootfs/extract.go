//go:build linux

package rootfs

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"strings"
)

// rootfsLimits bounds extracted and cached trees independently of archive size.
type rootfsLimits struct {
	MaxTotalBytes int64
	MaxFileBytes  int64
	MaxEntries    int
}

// defaultRootfsLimits is the shared resource-exhaustion policy for trees.
var defaultRootfsLimits = rootfsLimits{
	MaxTotalBytes: 512 << 20,
	MaxFileBytes:  128 << 20,
	MaxEntries:    100000,
}

func extractArchive(archivePath, destination string, limits rootfsLimits) error {
	archive, err := os.Open(archivePath)
	if err != nil {
		return fmt.Errorf("cannot open rootfs archive: %v", err)
	}
	defer archive.Close()

	compressed, err := gzip.NewReader(archive)
	if err != nil {
		return fmt.Errorf("cannot read rootfs gzip stream: %v", err)
	}
	defer compressed.Close()

	reader := tar.NewReader(compressed)
	entries := make(map[string]byte)
	directoryModes := make(map[string]fs.FileMode)
	var extractedBytes int64
	entryCount := 0

	for {
		header, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("cannot read rootfs tar stream: %v", err)
		}
		entryCount++
		if entryCount > limits.MaxEntries {
			return fmt.Errorf("rootfs archive exceeds the %d-entry limit", limits.MaxEntries)
		}
		if len(header.PAXRecords) != 0 || len(header.Xattrs) != 0 {
			return fmt.Errorf("rootfs archive entry %q contains unsupported extended metadata", header.Name)
		}

		name, rootMarker, err := normalizeArchivePath(header.Name)
		if err != nil {
			return err
		}
		if rootMarker {
			if header.Typeflag != tar.TypeDir {
				return fmt.Errorf("rootfs archive root marker %q is not a directory", header.Name)
			}
			continue
		}
		if err := checkEntryConflicts(name, header.Typeflag, entries); err != nil {
			return err
		}
		if err := ensureParentDirectories(destination, name); err != nil {
			return err
		}

		switch header.Typeflag {
		case tar.TypeDir:
			if err := extractDirectory(destination, name, header.Mode, directoryModes); err != nil {
				return err
			}
		case tar.TypeReg, tar.TypeRegA:
			if header.Size < 0 || header.Size > limits.MaxFileBytes {
				return fmt.Errorf("rootfs file %q exceeds the %d-byte file limit", name, limits.MaxFileBytes)
			}
			if extractedBytes > limits.MaxTotalBytes-header.Size {
				return fmt.Errorf("rootfs archive exceeds the %d-byte extracted-data limit", limits.MaxTotalBytes)
			}
			if err := extractRegularFile(destination, name, header.Mode, header.Size, reader); err != nil {
				return err
			}
			extractedBytes += header.Size
		case tar.TypeSymlink:
			if err := validateInternalTarget(name, header.Linkname); err != nil {
				return err
			}
			if err := extractSymlink(destination, name, header.Linkname); err != nil {
				return err
			}
		case tar.TypeLink:
			if err := extractHardlink(destination, name, header.Linkname); err != nil {
				return err
			}
		default:
			return fmt.Errorf("rootfs archive entry %q uses unsupported type %d", name, header.Typeflag)
		}
		entries[name] = header.Typeflag
	}

	for name, mode := range directoryModes {
		if err := os.Chmod(filepathJoin(destination, name), mode.Perm()); err != nil {
			return fmt.Errorf("cannot apply mode to rootfs directory %q: %v", name, err)
		}
	}
	return nil
}

func normalizeArchivePath(name string) (string, bool, error) {
	if name == "" || strings.IndexByte(name, 0) >= 0 {
		return "", false, fmt.Errorf("rootfs archive contains an empty or NUL path")
	}
	if strings.HasPrefix(name, "/") {
		return "", false, fmt.Errorf("rootfs archive path %q is absolute", name)
	}
	if name == "." || name == "./" {
		return "", true, nil
	}
	for strings.HasPrefix(name, "./") {
		name = strings.TrimPrefix(name, "./")
	}
	if name == "" {
		return "", false, fmt.Errorf("rootfs archive contains an empty path")
	}
	if strings.HasSuffix(name, "/") {
		name = strings.TrimSuffix(name, "/")
		if name == "" || strings.HasSuffix(name, "/") {
			return "", false, fmt.Errorf("rootfs archive contains an empty path component")
		}
	}
	for _, component := range strings.Split(name, "/") {
		if component == "" || component == "." || component == ".." {
			return "", false, fmt.Errorf("rootfs archive path %q is not a safe relative path", name)
		}
	}
	clean := path.Clean(name)
	if clean != name || clean == "." || clean == ".." || strings.HasPrefix(clean, "../") {
		return "", false, fmt.Errorf("rootfs archive path %q escapes the extraction root", name)
	}
	return clean, false, nil
}

func checkEntryConflicts(name string, kind byte, entries map[string]byte) error {
	if previous, ok := entries[name]; ok {
		return fmt.Errorf("rootfs archive contains duplicate entry %q (types %d and %d)", name, previous, kind)
	}
	for parent := path.Dir(name); parent != "."; parent = path.Dir(parent) {
		if previous, ok := entries[parent]; ok && previous != tar.TypeDir {
			return fmt.Errorf("rootfs archive entry %q traverses non-directory %q", name, parent)
		}
	}
	if kind != tar.TypeDir {
		prefix := name + "/"
		for existing := range entries {
			if strings.HasPrefix(existing, prefix) {
				return fmt.Errorf("rootfs archive entry %q conflicts with child %q", name, existing)
			}
		}
	}
	return nil
}

func ensureParentDirectories(destination, name string) error {
	parent := path.Dir(name)
	if parent == "." {
		return nil
	}
	current := destination
	for _, component := range strings.Split(parent, "/") {
		current = filepathJoin(current, component)
		info, err := os.Lstat(current)
		if os.IsNotExist(err) {
			if err := os.Mkdir(current, 0700); err != nil {
				return fmt.Errorf("cannot create rootfs parent %q: %v", component, err)
			}
			continue
		}
		if err != nil {
			return fmt.Errorf("cannot inspect rootfs parent %q: %v", component, err)
		}
		if !info.IsDir() {
			return fmt.Errorf("rootfs entry %q traverses a non-directory parent", name)
		}
	}
	return nil
}

func extractDirectory(destination, name string, mode int64, modes map[string]fs.FileMode) error {
	pathName := filepathJoin(destination, name)
	info, err := os.Lstat(pathName)
	if os.IsNotExist(err) {
		if err := os.Mkdir(pathName, fs.FileMode(mode).Perm()|0700); err != nil {
			return fmt.Errorf("cannot create rootfs directory %q: %v", name, err)
		}
	} else if err != nil {
		return fmt.Errorf("cannot inspect rootfs directory %q: %v", name, err)
	} else if !info.IsDir() {
		return fmt.Errorf("rootfs directory %q conflicts with an existing entry", name)
	}
	modes[name] = fs.FileMode(mode).Perm()
	return nil
}

func extractRegularFile(destination, name string, mode int64, size int64, reader io.Reader) error {
	pathName := filepathJoin(destination, name)
	file, err := os.OpenFile(pathName, os.O_WRONLY|os.O_CREATE|os.O_EXCL, fs.FileMode(mode).Perm())
	if err != nil {
		return fmt.Errorf("cannot create rootfs file %q: %v", name, err)
	}
	if _, err := io.CopyN(file, reader, size); err != nil {
		file.Close()
		os.Remove(pathName)
		return fmt.Errorf("cannot extract rootfs file %q: %v", name, err)
	}
	if err := file.Chmod(fs.FileMode(mode).Perm()); err != nil {
		file.Close()
		os.Remove(pathName)
		return fmt.Errorf("cannot apply mode to rootfs file %q: %v", name, err)
	}
	if err := file.Close(); err != nil {
		os.Remove(pathName)
		return fmt.Errorf("cannot close rootfs file %q: %v", name, err)
	}
	return nil
}

func extractSymlink(destination, name, target string) error {
	pathName := filepathJoin(destination, name)
	if _, err := os.Lstat(pathName); err == nil {
		return fmt.Errorf("rootfs symlink %q conflicts with an existing entry", name)
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("cannot inspect rootfs symlink %q: %v", name, err)
	}
	if err := os.Symlink(target, pathName); err != nil {
		return fmt.Errorf("cannot create rootfs symlink %q: %v", name, err)
	}
	return nil
}

func extractHardlink(destination, name, target string) error {
	normalizedTarget, rootMarker, err := normalizeArchivePath(target)
	if err != nil {
		return fmt.Errorf("rootfs hard link %q has an invalid target: %v", name, err)
	}
	if rootMarker {
		return fmt.Errorf("rootfs hard link %q has an invalid target: archive root", name)
	}
	targetPath := filepathJoin(destination, normalizedTarget)
	info, err := os.Lstat(targetPath)
	if err != nil {
		return fmt.Errorf("rootfs hard link %q targets unavailable entry %q: %v", name, normalizedTarget, err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("rootfs hard link %q targets non-regular entry %q", name, normalizedTarget)
	}
	if err := os.Link(targetPath, filepathJoin(destination, name)); err != nil {
		return fmt.Errorf("cannot create rootfs hard link %q: %v", name, err)
	}
	return nil
}

func validateInternalTarget(name, target string) error {
	if target == "" || strings.IndexByte(target, 0) >= 0 {
		return fmt.Errorf("rootfs symlink %q has an empty or NUL target", name)
	}
	var candidate string
	if strings.HasPrefix(target, "/") {
		if strings.HasPrefix(target, "//") {
			return fmt.Errorf("rootfs symlink %q has an invalid absolute target", name)
		}
		candidate = strings.TrimPrefix(target, "/")
	} else {
		candidate = path.Join(path.Dir(name), target)
	}
	if candidate == "" {
		return nil
	}
	clean := path.Clean(candidate)
	if clean == ".." || strings.HasPrefix(clean, "../") {
		return fmt.Errorf("rootfs symlink %q escapes the extraction root", name)
	}
	return nil
}

func filepathJoin(base, relative string) string {
	return base + string(os.PathSeparator) + strings.ReplaceAll(relative, "/", string(os.PathSeparator))
}
