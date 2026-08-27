//go:build linux

package rootfs

import (
	"archive/tar"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"sort"
	"strings"

	"github.com/mholt/archives"
)

// rootfsLimits bounds extracted and cached trees independently of archive size.
type rootfsLimits struct {
	MaxTotalBytes int64
	MaxFileBytes  int64
	MaxEntries    int
}

type extractionStats struct {
	TotalBytes       int64
	LargestFileBytes int64
	Entries          int
}

// defaultRootfsLimits is the shared resource-exhaustion policy for trees.
var defaultRootfsLimits = rootfsLimits{
	MaxTotalBytes: 512 << 20,
	MaxFileBytes:  128 << 20,
	MaxEntries:    100000,
}

func extractArchive(archivePath, destination string, limits rootfsLimits) (extractionStats, error) {
	archive, err := os.Open(archivePath)
	if err != nil {
		return extractionStats{}, fmt.Errorf("cannot open rootfs archive: %w", err)
	}
	defer archive.Close()

	format, stream, err := archives.Identify(context.Background(), "", archive)
	if err != nil {
		return extractionStats{}, fmt.Errorf("cannot identify rootfs archive: %w", err)
	}
	extractor, ok := format.(archives.Extractor)
	if !ok {
		return extractionStats{}, fmt.Errorf("rootfs input is a recognized compressed file, not an archive")
	}

	entries := make(map[string]byte)
	directoryModes := make(map[string]fs.FileMode)
	var extractedBytes int64
	var largestFileBytes int64
	entryCount := 0
	err = extractor.Extract(context.Background(), stream, func(_ context.Context, file archives.FileInfo) error {
		entryCount++
		if entryCount > limits.MaxEntries {
			return fmt.Errorf("rootfs archive exceeds the %d-entry limit", limits.MaxEntries)
		}

		name, rootMarker, err := normalizeArchivePath(file.NameInArchive)
		if err != nil {
			return err
		}
		if rootMarker {
			if !file.IsDir() {
				return fmt.Errorf("rootfs archive root marker %q is not a directory", file.NameInArchive)
			}
			return nil
		}
		kind, err := archiveEntryKind(file)
		if err != nil {
			return fmt.Errorf("rootfs archive entry %q: %w", name, err)
		}
		if err := checkEntryConflicts(name, kind, entries); err != nil {
			return err
		}
		if err := ensureParentDirectories(destination, name); err != nil {
			return err
		}

		switch kind {
		case tar.TypeDir:
			if err := extractDirectory(destination, name, int64(file.Mode().Perm()), directoryModes); err != nil {
				return err
			}
		case tar.TypeReg, tar.TypeRegA:
			if err := extractRegularFile(destination, name, file, limits, &extractedBytes); err != nil {
				return err
			}
			if file.Size() > largestFileBytes {
				largestFileBytes = file.Size()
			}
		case tar.TypeSymlink:
			if err := validateInternalTarget(name, file.LinkTarget); err != nil {
				return err
			}
			if err := extractSymlink(destination, name, file.LinkTarget); err != nil {
				return err
			}
		case tar.TypeLink:
			if err := extractHardlink(destination, name, file.LinkTarget); err != nil {
				return err
			}
		default:
			return fmt.Errorf("rootfs archive entry %q uses unsupported type", name)
		}
		entries[name] = kind
		return nil
	})
	if err != nil {
		return extractionStats{}, fmt.Errorf("cannot extract rootfs archive: %w", err)
	}

	directoryNames := make([]string, 0, len(directoryModes))
	for name := range directoryModes {
		directoryNames = append(directoryNames, name)
	}
	sort.Slice(directoryNames, func(i, j int) bool {
		depth := func(name string) int { return strings.Count(name, "/") + 1 }
		leftDepth, rightDepth := depth(directoryNames[i]), depth(directoryNames[j])
		if leftDepth != rightDepth {
			return leftDepth > rightDepth
		}
		return directoryNames[i] < directoryNames[j]
	})
	for _, name := range directoryNames {
		mode := directoryModes[name]
		if err := os.Chmod(filepathJoin(destination, name), mode.Perm()); err != nil {
			return extractionStats{}, fmt.Errorf("cannot apply mode to rootfs directory %q: %w", name, err)
		}
	}
	return extractionStats{TotalBytes: extractedBytes, LargestFileBytes: largestFileBytes, Entries: entryCount}, nil
}

func archiveEntryKind(file archives.FileInfo) (byte, error) {
	mode := file.Mode()
	switch {
	case mode.IsDir():
		return tar.TypeDir, nil
	case mode&fs.ModeSymlink != 0:
		return tar.TypeSymlink, nil
	case !mode.IsRegular():
		return 0, fmt.Errorf("uses unsupported type")
	}
	if header, ok := file.Header.(*tar.Header); ok && header.Typeflag == tar.TypeLink {
		return tar.TypeLink, nil
	}
	return tar.TypeReg, nil
}

func extractRegularFile(destination, name string, file archives.FileInfo, limits rootfsLimits, extractedBytes *int64) (err error) {
	declaredSize := file.Size()
	if declaredSize < 0 || declaredSize > limits.MaxFileBytes {
		return fmt.Errorf("rootfs file %q exceeds the %d-byte file limit", name, limits.MaxFileBytes)
	}
	remaining := limits.MaxTotalBytes - *extractedBytes
	if remaining < 0 {
		return fmt.Errorf("rootfs archive exceeds the %d-byte extracted-data limit", limits.MaxTotalBytes)
	}
	readLimit := limits.MaxFileBytes
	if remaining < readLimit {
		readLimit = remaining
	}
	input, err := file.Open()
	if err != nil {
		return fmt.Errorf("cannot open rootfs file %q: %w", name, err)
	}
	defer func() {
		if closeErr := input.Close(); closeErr != nil {
			err = errors.Join(err, fmt.Errorf("cannot close rootfs file %q input: %w", name, closeErr))
		}
	}()

	pathName := filepathJoin(destination, name)
	output, err := os.OpenFile(pathName, os.O_WRONLY|os.O_CREATE|os.O_EXCL, file.Mode().Perm())
	if err != nil {
		return fmt.Errorf("cannot create rootfs file %q: %w", name, err)
	}
	remove := true
	defer func() {
		if remove {
			_ = os.Remove(pathName)
		}
	}()

	count, copyErr := io.Copy(output, io.LimitReader(input, readLimit+1))
	if copyErr != nil {
		_ = output.Close()
		return fmt.Errorf("cannot extract rootfs file %q: %w", name, copyErr)
	}
	if count > readLimit || count != declaredSize {
		_ = output.Close()
		if count > readLimit {
			if readLimit == limits.MaxFileBytes {
				return fmt.Errorf("rootfs file %q exceeds the %d-byte file limit", name, limits.MaxFileBytes)
			}
			return fmt.Errorf("rootfs archive exceeds the %d-byte extracted-data limit", limits.MaxTotalBytes)
		}
		return fmt.Errorf("rootfs file %q size changed while being extracted", name)
	}
	var extra [1]byte
	extraCount, extraErr := input.Read(extra[:])
	if extraCount != 0 {
		_ = output.Close()
		return fmt.Errorf("rootfs file %q contains more data than declared", name)
	}
	if extraErr != nil && extraErr != io.EOF {
		_ = output.Close()
		return fmt.Errorf("cannot finish rootfs file %q: %w", name, extraErr)
	}
	if err := output.Chmod(file.Mode().Perm()); err != nil {
		_ = output.Close()
		return fmt.Errorf("cannot apply mode to rootfs file %q: %w", name, err)
	}
	if err := output.Close(); err != nil {
		return fmt.Errorf("cannot close rootfs file %q: %w", name, err)
	}
	remove = false
	*extractedBytes += count
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
