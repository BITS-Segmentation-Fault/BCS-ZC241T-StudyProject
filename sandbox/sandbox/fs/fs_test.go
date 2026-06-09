package fs

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadWriteText_Parity(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "sandbox_fs_test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	targetFile := filepath.Join(tmpDir, "sample.txt")
	testContent := "hello container runtime"

	if err := WriteText(targetFile, testContent); err != nil {
		t.Fatalf("WriteText failed: %v", err)
	}

	got := ReadText(targetFile)
	if got != testContent {
		t.Errorf("Expected %q, got %q", testContent, got)
	}

	missing := ReadText(filepath.Join(tmpDir, "does-not-exist.dat"))
	if missing != "<missing>" {
		t.Errorf("Expected '<missing>' token, got %q", missing)
	}
}
