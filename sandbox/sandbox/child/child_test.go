//go:build linux

package child

import (
	"math"
	"testing"
)

func TestDropCapabilitiesRejectsUnknownNames(t *testing.T) {
	if err := dropCapabilities([]string{"CAP_NOT_REAL"}); err == nil {
		t.Fatal("dropCapabilities() accepted an unknown capability")
	}
}

func TestDropCapabilitiesAcceptsEmptyList(t *testing.T) {
	if err := dropCapabilities(nil); err != nil {
		t.Fatalf("dropCapabilities(nil) error = %v", err)
	}
}

func TestResourceBytesRejectsOverflow(t *testing.T) {
	if _, err := resourceBytes(math.MaxInt, 1024*1024*1024, "memory_limit_gb"); err == nil {
		t.Fatal("resourceBytes() accepted an overflowing value")
	}
}
