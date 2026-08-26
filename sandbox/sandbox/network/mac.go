package network

import (
	"crypto/rand"
	"fmt"
	"io"
)

func generateRandomMAC(r io.Reader) ([]byte, error) {
	if r == nil {
		r = rand.Reader
	}
	mac := make([]byte, 6)
	if _, err := io.ReadFull(r, mac); err != nil {
		return nil, fmt.Errorf("failed to read random bytes: %w", err)
	}
	mac[0] = (mac[0] | 2) &^ 1
	return mac, nil
}
