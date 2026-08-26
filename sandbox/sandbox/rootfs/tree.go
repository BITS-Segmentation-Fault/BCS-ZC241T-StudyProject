//go:build linux

package rootfs

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"os"
	"path"
	"sort"
	"strings"

	"golang.org/x/sys/unix"
)

const treeDigestVersion = "sandbox-rootfs-tree-v1"

type rootfsEntry struct {
	fd     int
	stat   unix.Stat_t
	target string
}

func treeDigest(root string) (string, error) {
	fd, err := openDirectoryPath(root)
	if err != nil {
		return "", err
	}
	defer unix.Close(fd)
	return treeDigestFD(fd)
}

func treeDigestFD(rootFD int) (string, error) {
	digest := sha256.New()
	_, _ = digest.Write([]byte(treeDigestVersion))
	if err := walkTree(rootFD, "", digest, new(int64)); err != nil {
		return "", err
	}
	return hex.EncodeToString(digest.Sum(nil)), nil
}

func walkTree(directoryFD int, relative string, digest hash.Hash, extractedBytes *int64) error {
	names, err := readDirectoryNames(directoryFD)
	if err != nil {
		return fmt.Errorf("cannot read rootfs directory %q: %v", relative, err)
	}
	for _, name := range names {
		child := name
		if relative != "" {
			child = path.Join(relative, name)
		}
		if relative == "" && name == manifestName {
			continue
		}
		entry, err := openEntryAt(directoryFD, name)
		if err != nil {
			return fmt.Errorf("cannot securely inspect rootfs entry %q: %v", child, err)
		}
		if err := writeEntryHeader(digest, child, entry.stat, entry.target); err != nil {
			unix.Close(entry.fd)
			return err
		}
		switch entry.stat.Mode & unix.S_IFMT {
		case unix.S_IFDIR:
			err = walkTree(entry.fd, child, digest, extractedBytes)
		case unix.S_IFREG:
			err = hashRegularFile(entry.fd, child, entry.stat.Size, extractedBytes, digest)
		case unix.S_IFLNK:
			if err = validateInternalTarget(child, entry.target); err != nil {
				err = fmt.Errorf("rootfs symlink %q is invalid: %v", child, err)
			}
		default:
			err = fmt.Errorf("rootfs entry %q uses unsupported node type", child)
		}
		unix.Close(entry.fd)
		if err != nil {
			return err
		}
	}
	return nil
}

func writeEntryHeader(digest hash.Hash, name string, stat unix.Stat_t, target string) error {
	var kind byte
	switch stat.Mode & unix.S_IFMT {
	case unix.S_IFDIR:
		kind = 'd'
	case unix.S_IFREG:
		kind = 'f'
	case unix.S_IFLNK:
		kind = 'l'
	default:
		return fmt.Errorf("rootfs entry %q uses unsupported node type", name)
	}
	_, _ = digest.Write([]byte{kind})
	writeDigestBytes(digest, []byte(name))
	var mode [4]byte
	binary.BigEndian.PutUint32(mode[:], uint32(stat.Mode&0777))
	_, _ = digest.Write(mode[:])
	size := uint64(0)
	if kind == 'f' {
		if stat.Size < 0 {
			return fmt.Errorf("rootfs file %q has a negative size", name)
		}
		size = uint64(stat.Size)
	}
	var encodedSize [8]byte
	binary.BigEndian.PutUint64(encodedSize[:], size)
	_, _ = digest.Write(encodedSize[:])
	if kind == 'l' {
		writeDigestBytes(digest, []byte(target))
	}
	return nil
}

func writeDigestBytes(digest hash.Hash, value []byte) {
	var length [8]byte
	binary.BigEndian.PutUint64(length[:], uint64(len(value)))
	_, _ = digest.Write(length[:])
	_, _ = digest.Write(value)
}

func hashRegularFile(fd int, name string, size int64, extractedBytes *int64, digest hash.Hash) error {
	if size < 0 || size > defaultExtractionLimits.MaxFileBytes {
		return fmt.Errorf("rootfs file %q exceeds the %d-byte file limit", name, defaultExtractionLimits.MaxFileBytes)
	}
	if *extractedBytes > defaultExtractionLimits.MaxExtractedBytes-size {
		return fmt.Errorf("rootfs tree exceeds the %d-byte extracted-data limit", defaultExtractionLimits.MaxExtractedBytes)
	}
	duplicate, err := unix.Dup(fd)
	if err != nil {
		return fmt.Errorf("cannot duplicate rootfs file %q: %v", name, err)
	}
	file := os.NewFile(uintptr(duplicate), name)
	if file == nil {
		unix.Close(duplicate)
		return fmt.Errorf("cannot open rootfs file %q", name)
	}
	read, err := io.CopyN(digest, file, size)
	if err == nil && read != size {
		err = io.ErrUnexpectedEOF
	}
	if err == nil {
		var extra [1]byte
		n, readErr := file.Read(extra[:])
		if n != 0 {
			err = fmt.Errorf("rootfs file %q changed while being hashed", name)
		} else if readErr != io.EOF {
			err = readErr
		}
	}
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return fmt.Errorf("cannot hash rootfs file %q: %v", name, err)
	}
	*extractedBytes += size
	return nil
}

func openEntryAt(parentFD int, name string) (rootfsEntry, error) {
	fd, err := unix.Openat(parentFD, name, unix.O_PATH|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return rootfsEntry{}, err
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		unix.Close(fd)
		return rootfsEntry{}, err
	}
	typeBits := stat.Mode & unix.S_IFMT
	if typeBits == unix.S_IFLNK {
		target, err := readlinkAt(parentFD, name)
		if err != nil {
			unix.Close(fd)
			return rootfsEntry{}, err
		}
		return rootfsEntry{fd: fd, stat: stat, target: target}, nil
	}
	if typeBits != unix.S_IFDIR && typeBits != unix.S_IFREG {
		return rootfsEntry{fd: fd, stat: stat}, nil
	}
	flags := unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NOFOLLOW
	if typeBits == unix.S_IFDIR {
		flags |= unix.O_DIRECTORY
	}
	readFD, err := unix.Openat(parentFD, name, flags, 0)
	if err != nil {
		unix.Close(fd)
		return rootfsEntry{}, err
	}
	var readStat unix.Stat_t
	if err := unix.Fstat(readFD, &readStat); err != nil {
		unix.Close(readFD)
		unix.Close(fd)
		return rootfsEntry{}, err
	}
	if readStat.Dev != stat.Dev || readStat.Ino != stat.Ino || readStat.Mode&unix.S_IFMT != typeBits {
		unix.Close(readFD)
		unix.Close(fd)
		return rootfsEntry{}, fmt.Errorf("rootfs entry %q changed while being opened", name)
	}
	unix.Close(fd)
	return rootfsEntry{fd: readFD, stat: readStat}, nil
}

func openRelativeEntry(rootFD int, relative string) (rootfsEntry, error) {
	if relative == "" || path.IsAbs(relative) || relative == "." || relative == ".." || len(relative) >= 2 && relative[:2] == "../" {
		return rootfsEntry{}, fmt.Errorf("unsafe relative rootfs entry %q", relative)
	}
	parts := strings.Split(relative, "/")
	for _, part := range parts {
		if part == "" || part == "." || part == ".." {
			return rootfsEntry{}, fmt.Errorf("unsafe relative rootfs entry %q", relative)
		}
	}
	parentFD, err := unix.Dup(rootFD)
	if err != nil {
		return rootfsEntry{}, err
	}
	defer unix.Close(parentFD)
	for _, part := range parts[:len(parts)-1] {
		next, err := openDirectoryAt(parentFD, part)
		if err != nil {
			return rootfsEntry{}, err
		}
		unix.Close(parentFD)
		parentFD = next
	}
	return openEntryAt(parentFD, parts[len(parts)-1])
}

func readlinkAt(parentFD int, name string) (string, error) {
	buffer := make([]byte, 4096)
	count, err := unix.Readlinkat(parentFD, name, buffer)
	if err != nil {
		return "", err
	}
	if count == len(buffer) {
		return "", fmt.Errorf("symlink target is too long")
	}
	return string(buffer[:count]), nil
}

func readDirectoryNames(fd int) ([]string, error) {
	duplicate, err := unix.Dup(fd)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(duplicate), "rootfs-directory")
	if file == nil {
		unix.Close(duplicate)
		return nil, fmt.Errorf("cannot duplicate rootfs directory")
	}
	entries, readErr := file.ReadDir(-1)
	closeErr := file.Close()
	if readErr != nil {
		return nil, readErr
	}
	if closeErr != nil {
		return nil, closeErr
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	sort.Strings(names)
	return names, nil
}
