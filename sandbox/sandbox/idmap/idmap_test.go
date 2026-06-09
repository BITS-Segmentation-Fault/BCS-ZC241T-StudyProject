package idmap

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestReadSubIDRanges_ParityAndErrors(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "idmap_test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	subuidFile := filepath.Join(tmpDir, "subuid")
	mockContent := "julian:100000:65536\n# comment line\nroot:200000:1000\njulian:200000:1000\n"
	if err := os.WriteFile(subuidFile, []byte(mockContent), 0644); err != nil {
		t.Fatal(err)
	}

	// 1. Check valid parse optimization
	got, err := ReadSubIDRanges(subuidFile, "julian")
	if err != nil {
		t.Fatalf("Unexpected error parsing subuid: %v", err)
	}

	want := []IDRange{
		{StartID: 100000, Count: 65536},
		{StartID: 200000, Count: 1000},
	}

	if !reflect.DeepEqual(got, want) {
		t.Errorf("ReadSubIDRanges got %+v, want %+v", got, want)
	}

	_, err = ReadSubIDRanges(subuidFile, "unknown_user")
	if err == nil {
		t.Error("Expected an error for non-existent user match, got nil")
	}
}

func TestBuildIDMap(t *testing.T) {
	subRanges := []IDRange{{StartID: 100000, Count: 10}}
	got := BuildIDMap(1000, subRanges)

	want := []Mapping{
		{ContainerID: 0, HostID: 1000, Count: 1},
		{ContainerID: 1, HostID: 100000, Count: 10},
	}

	if !reflect.DeepEqual(got, want) {
		t.Errorf("BuildIDMap got %+v, want %+v", got, want)
	}
}
