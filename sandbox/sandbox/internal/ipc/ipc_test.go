package ipc

import (
	"os"
	"reflect"
	"testing"

	"sandbox/sandbox/config"
)

func TestConfigSnapshotRoundTrip(t *testing.T) {
	left, right, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.DefaultConfig()
	cfg.Command = []string{"/bin/echo", "hello", ""}
	cfg.RootFSSource = "/tmp/rootfs"
	cfg.FileSizeLimitMB = 4
	done := make(chan error, 1)
	go func() { done <- WriteConfig(right, cfg); _ = right.Close() }()
	got, err := ReadConfig(left)
	_ = left.Close()
	if err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, cfg) {
		t.Fatalf("snapshot changed config: %+v", got)
	}
}

func TestConfigSnapshotRejectsMalformedJSON(t *testing.T) {
	for _, data := range []string{`{"command":["/bin/echo"],"unknown":1}`, `{"command":["/bin/echo"]} garbage`} {
		left, right, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		frame := append([]byte{byte(len(data) >> 24), byte(len(data) >> 16), byte(len(data) >> 8), byte(len(data))}, []byte(data)...)
		if _, err := right.Write(frame); err != nil {
			t.Fatal(err)
		}
		_ = right.Close()
		if _, err := ReadConfig(left); err == nil {
			t.Errorf("accepted malformed snapshot %q", data)
		}
		_ = left.Close()
	}
}

func TestConfigSnapshotRejectsInvalidConfiguration(t *testing.T) {
	left, right, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	data := []byte(`{"command":[]}`)
	frame := append([]byte{byte(len(data) >> 24), byte(len(data) >> 16), byte(len(data) >> 8), byte(len(data))}, data...)
	if _, err := right.Write(frame); err != nil {
		t.Fatal(err)
	}
	_ = right.Close()
	if _, err := ReadConfig(left); err == nil {
		t.Fatal("accepted invalid snapshot configuration")
	}
	_ = left.Close()
}

func TestConfigSnapshotRejectsOversize(t *testing.T) {
	left, right, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	frame := []byte{0x00, 0x10, 0x00, 0x01}
	if _, err := right.Write(frame); err != nil {
		t.Fatal(err)
	}
	_ = right.Close()
	if _, err := ReadConfig(left); err == nil {
		t.Fatal("accepted oversized snapshot")
	}
	_ = left.Close()
}
