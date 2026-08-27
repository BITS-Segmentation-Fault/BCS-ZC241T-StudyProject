//go:build linux

package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"sandbox/sandbox/config"
	"sandbox/sandbox/network"
)

func remoteRootfsArchive(t *testing.T, probe string) []byte {
	t.Helper()
	probeData, err := os.ReadFile(probe)
	if err != nil {
		t.Fatal(err)
	}
	entries := []struct {
		name string
		mode int64
		data []byte
	}{
		{name: "./", mode: 0755},
		{name: "./bin/", mode: 0755},
		{name: "./etc/", mode: 0755},
		{name: "./proc/", mode: 0555},
		{name: "./work/", mode: 0755},
		{name: "./etc/resolv.conf", mode: 0644},
		{name: "./bin/probe", mode: 0755, data: probeData},
	}
	var output bytes.Buffer
	compressed := gzip.NewWriter(&output)
	archive := tar.NewWriter(compressed)
	for _, entry := range entries {
		header := &tar.Header{Name: entry.name, Mode: entry.mode, Typeflag: tar.TypeReg}
		if strings.HasSuffix(entry.name, "/") {
			header.Typeflag = tar.TypeDir
		}
		header.Size = int64(len(entry.data))
		if err := archive.WriteHeader(header); err != nil {
			t.Fatal(err)
		}
		if _, err := archive.Write(entry.data); err != nil {
			t.Fatal(err)
		}
	}
	if err := archive.Close(); err != nil {
		t.Fatal(err)
	}
	if err := compressed.Close(); err != nil {
		t.Fatal(err)
	}
	return output.Bytes()
}

func startRemoteRootfsServer(t *testing.T, archive []byte) (*httptest.Server, string) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		skipOrFail(t, fmt.Sprintf("local TLS listener is unavailable: %v", err))
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/gzip")
		_, _ = writer.Write(archive)
	}))
	server.Listener = listener
	server.StartTLS()
	t.Cleanup(server.Close)

	certificate := filepath.Join(t.TempDir(), "server.pem")
	data := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	if err := os.WriteFile(certificate, data, 0600); err != nil {
		t.Fatal(err)
	}
	return server, certificate
}

func remoteRootfsConfig(serverURL, archiveSHA256 string) config.Config {
	cfg := config.DefaultConfig()
	cfg.Command = []string{"/bin/probe", "environment", "REMOTE_VALUE"}
	cfg.EnvVars = []string{"REMOTE_VALUE=remote-value"}
	cfg.EnvWhitelist = nil
	cfg.RootFSSource = ""
	cfg.RemoteRootFS = &config.RemoteRootFS{
		URL:           serverURL + "/rootfs.tar.gz",
		Architecture:  runtime.GOARCH,
		ArchiveSHA256: archiveSHA256,
	}
	cfg.ReadOnlyRoot = true
	cfg.NetworkMode = network.None
	return cfg
}

func TestSandboxRemoteRootFS(t *testing.T) {
	if os.Getenv("SANDBOX_REMOTE_ROOTFS_E2E") != "1" {
		t.Skip("remote-rootfs E2E requires SANDBOX_REMOTE_ROOTFS_E2E=1")
	}
	namespacesAvailable(t)
	archive := remoteRootfsArchive(t, probeTestBinary(t))
	digest := sha256.Sum256(archive)
	server, certificate := startRemoteRootfsServer(t, archive)
	t.Setenv("SSL_CERT_FILE", certificate)
	t.Setenv("NO_PROXY", "127.0.0.1,localhost")

	cache := t.TempDir()
	cfg := remoteRootfsConfig(server.URL, hex.EncodeToString(digest[:]))
	command := exec.Command(sandboxTestBinary(t), "--config", writeSandboxConfig(t, cfg))
	command.Env = withEnvironment(os.Environ(), "XDG_CACHE_HOME", cache)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("remote rootfs launch failed: %v\n%s", err, output)
	}
	if string(output) != "environment=REMOTE_VALUE=remote-value\n" {
		t.Fatalf("remote rootfs payload output = %q", output)
	}
	server.Close()

	offline := exec.Command(sandboxTestBinary(t), "--config", writeSandboxConfig(t, cfg))
	offline.Env = withEnvironment(os.Environ(), "XDG_CACHE_HOME", cache)
	output, err = offline.CombinedOutput()
	if err != nil {
		t.Fatalf("offline remote rootfs launch failed: %v\n%s", err, output)
	}
	if string(output) != "environment=REMOTE_VALUE=remote-value\n" {
		t.Fatalf("offline remote rootfs payload output = %q", output)
	}
}

func TestSandboxRemoteRootFSRejectsWrongArchiveHash(t *testing.T) {
	archive := remoteRootfsArchive(t, probeTestBinary(t))
	digest := sha256.Sum256(archive)
	server, certificate := startRemoteRootfsServer(t, archive)
	t.Setenv("SSL_CERT_FILE", certificate)
	t.Setenv("NO_PROXY", "127.0.0.1,localhost")

	wanted := strings.Repeat("0", 64)
	if wanted == hex.EncodeToString(digest[:]) {
		wanted = strings.Repeat("1", 64)
	}
	cache := t.TempDir()
	cfg := remoteRootfsConfig(server.URL, wanted)
	command := exec.Command(sandboxTestBinary(t), "--config", writeSandboxConfig(t, cfg))
	command.Env = withEnvironment(os.Environ(), "XDG_CACHE_HOME", cache)
	output, err := command.CombinedOutput()
	if err == nil || !strings.Contains(string(output), "archive SHA-256 mismatch") {
		t.Fatalf("wrong archive hash result = %v\n%s", err, output)
	}
	remoteCache := filepath.Join(cache, "bcs-zc241t-sandbox", "rootfs", "remote", "v1", wanted)
	if _, err := os.Lstat(remoteCache); !os.IsNotExist(err) {
		t.Fatalf("wrong-hash launch published a cache: %v", err)
	}
}
