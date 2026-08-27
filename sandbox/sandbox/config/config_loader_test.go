package config

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestLoadConfigDefaultsAndOverride(t *testing.T) {
	c, err := LoadConfigFromReader(strings.NewReader("command: [/bin/echo, hello]\n"))
	if err != nil {
		t.Fatal(err)
	}
	if c.BlockedSyscallAction != ActionKill || c.FileSizeLimitMB != 100 || c.CPULimitPercent != 0 || c.MemoryLimitGB != 0 || c.MaxProcesses != 0 || c.RootFSSource != "" || c.WorkingDir != "/" {
		t.Fatalf("defaults lost: %+v", c)
	}
	c, err = LoadConfigFromReader(strings.NewReader("command: [/bin/echo]\nblocked_syscall_action: trap\nfile_size_limit_mb: 4\n"))
	if err != nil || c.BlockedSyscallAction != ActionTrap || c.FileSizeLimitMB != 4 {
		t.Fatalf("override failed: %v %+v", err, c)
	}
}

func TestLoadConfigRejectsBoundaries(t *testing.T) {
	tests := []string{
		"command: [/bin/echo]\nunknown: true\n",
		"command: [/bin/echo]\n---\ncommand: [/bin/false]\n",
		"command: [/bin/echo]\nfile_size_limit_mb: -1\n",
	}
	for _, input := range tests {
		if _, err := LoadConfigFromReader(strings.NewReader(input)); err == nil {
			t.Errorf("accepted invalid YAML %q", input)
		}
	}
	oversized := strings.Repeat("x", maxConfigBytes+1)
	if _, err := LoadConfigFromReader(strings.NewReader(oversized)); err == nil {
		t.Error("accepted oversized configuration")
	}
}

func TestLoadConfigRemoteRootFS(t *testing.T) {
	input := "command: [/bin/echo]\nremote_rootfs:\n  url: https://mirror.example/rootfs.tar.gz\n  architecture: " + runtime.GOARCH + "\n  archive_sha256: " + strings.Repeat("a", 64) + "\n  max_extracted_size_mb: 2048\n  max_file_size_mb: 256\n  max_entries: 7000\n"
	c, err := LoadConfigFromReader(strings.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	if c.RemoteRootFS == nil || c.RemoteRootFS.URL != "https://mirror.example/rootfs.tar.gz" || c.RemoteRootFS.Architecture != runtime.GOARCH || c.RemoteRootFS.ArchiveSHA256 != strings.Repeat("a", 64) || c.RemoteRootFS.MaxExtractedSizeMB != 2048 || c.RemoteRootFS.MaxFileSizeMB != 256 || c.RemoteRootFS.MaxEntries != 7000 {
		t.Fatalf("remote rootfs was not loaded: %+v", c.RemoteRootFS)
	}

	unknown := input + "  unexpected: true\n"
	if _, err := LoadConfigFromReader(strings.NewReader(unknown)); err == nil {
		t.Fatal("accepted unknown remote_rootfs field")
	}
}

func TestLoadConfigResolvesHostPathsRelativeToFile(t *testing.T) {
	configDir := t.TempDir()
	currentDir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Clean(currentDir) == filepath.Clean(configDir) {
		t.Fatal("temporary config directory unexpectedly equals working directory")
	}
	absoluteHost := filepath.Join(t.TempDir(), "absolute")
	configPath := filepath.Join(configDir, "sandbox.yaml")
	contents := fmt.Sprintf("command: [/bin/echo]\nrootfs_source: rootfs\nworking_dir: /work\nbind_mounts:\n  - host_path: scripts\n    container_path: /scripts\n  - host_path: ../shared\n    container_path: /shared\n  - host_path: %q\n    container_path: /absolute\n", absoluteHost)
	if err := os.WriteFile(configPath, []byte(contents), 0600); err != nil {
		t.Fatal(err)
	}
	c, err := LoadConfig(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if c.RootFSSource != filepath.Join(configDir, "rootfs") {
		t.Fatalf("rootfs_source = %q, want %q", c.RootFSSource, filepath.Join(configDir, "rootfs"))
	}
	if c.BindMounts[0].HostPath != filepath.Join(configDir, "scripts") {
		t.Fatalf("relative bind source = %q, want %q", c.BindMounts[0].HostPath, filepath.Join(configDir, "scripts"))
	}
	if c.BindMounts[1].HostPath != filepath.Join(filepath.Dir(configDir), "shared") {
		t.Fatalf("parent bind source = %q, want %q", c.BindMounts[1].HostPath, filepath.Join(filepath.Dir(configDir), "shared"))
	}
	if c.BindMounts[2].HostPath != absoluteHost {
		t.Fatalf("absolute bind source = %q, want %q", c.BindMounts[2].HostPath, absoluteHost)
	}
	if c.WorkingDir != "/work" || c.BindMounts[0].ContainerPath != "/scripts" {
		t.Fatalf("guest paths were changed: working_dir=%q container_path=%q", c.WorkingDir, c.BindMounts[0].ContainerPath)
	}

	remotePath := filepath.Join(configDir, "remote.yaml")
	remoteURL := "https://mirror.example/rootfs.tar.gz"
	remoteContents := "command: [/bin/echo]\nremote_rootfs:\n  url: " + remoteURL + "\n  architecture: " + runtime.GOARCH + "\n  archive_sha256: " + strings.Repeat("a", 64) + "\n"
	if err := os.WriteFile(remotePath, []byte(remoteContents), 0600); err != nil {
		t.Fatal(err)
	}
	remoteConfig, err := LoadConfig(remotePath)
	if err != nil {
		t.Fatal(err)
	}
	if remoteConfig.RemoteRootFS.URL != remoteURL {
		t.Fatalf("remote URL = %q, want %q", remoteConfig.RemoteRootFS.URL, remoteURL)
	}

	emptyPath := filepath.Join(configDir, "empty.yaml")
	if err := os.WriteFile(emptyPath, []byte("command: [/bin/echo]\nbind_mounts:\n  - host_path: \"\"\n    container_path: /mnt\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(emptyPath); err == nil || !strings.Contains(err.Error(), "bind_mount host_path") {
		t.Fatalf("empty bind source error = %v", err)
	}

	readerInput := "command: [/bin/echo]\nbind_mounts:\n  - host_path: scripts\n    container_path: /scripts\n"
	if _, err := LoadConfigFromReader(strings.NewReader(readerInput)); err == nil || !strings.Contains(err.Error(), "bind_mount host_path") {
		t.Fatalf("reader accepted relative bind source: %v", err)
	}
}
