package network

import (
	"crypto/rand"
	"fmt"
	"io"
	"net"
)

func GenerateRandomMAC(r io.Reader) (net.HardwareAddr, error) {
	if r == nil {
		r = rand.Reader
	}
	buf := make([]byte, 5)
	_, err := io.ReadFull(r, buf)
	if err != nil {
		return nil, fmt.Errorf("failed to read random bytes: %v", err)
	}
	mac := append([]byte{0x02}, buf...)
	return net.HardwareAddr(mac), nil
}
