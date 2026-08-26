package network

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestNetworkModeValidation(t *testing.T) {
	for _, test := range []struct {
		mode  NetworkMode
		valid bool
	}{
		{Host, true}, {None, true}, {Bridge, true}, {"", false}, {"HOST", false}, {"host ", false},
	} {
		if got := test.mode.IsValid(); got != test.valid {
			t.Errorf("%q IsValid() = %v, want %v", test.mode, got, test.valid)
		}
	}
}

func TestBridgeConfigValidation(t *testing.T) {
	valid := DefaultBridgeConfig()
	for _, test := range []struct {
		name   string
		mutate func(*BridgeConfig)
	}{
		{"noncanonical subnet", func(c *BridgeConfig) { c.Subnet = "10.0.100.5/24" }},
		{"invalid subnet", func(c *BridgeConfig) { c.Subnet = "bad" }},
		{"network gateway", func(c *BridgeConfig) { c.GatewayIP = "10.0.100.0" }},
		{"broadcast container", func(c *BridgeConfig) { c.ContainerIP = "10.0.100.255" }},
		{"duplicate addresses", func(c *BridgeConfig) { c.ContainerIP = c.GatewayIP }},
		{"invalid gateway", func(c *BridgeConfig) { c.GatewayIP = "::1" }},
		{"invalid mtu", func(c *BridgeConfig) { c.MTU = 1 }},
	} {
		t.Run(test.name, func(t *testing.T) {
			cfg := valid
			test.mutate(&cfg)
			if err := cfg.Validate(); err == nil {
				t.Fatal("Validate() accepted invalid bridge configuration")
			}
		})
	}
	if err := valid.Validate(); err != nil {
		t.Fatalf("default bridge configuration is invalid: %v", err)
	}
}

func TestGenerateRandomMAC(t *testing.T) {
	mac, err := generateRandomMAC(strings.NewReader("\x01\x02\x03\x04\x05\x06"))
	if err != nil {
		t.Fatal(err)
	}
	if want := []byte{0x02, 2, 3, 4, 5, 6}; !bytes.Equal(mac, want) {
		t.Fatalf("MAC = %x, want %x", mac, want)
	}
	if _, err := generateRandomMAC(strings.NewReader("short")); err == nil {
		t.Fatal("short random input was accepted")
	}
	if mac[0]&1 != 0 || mac[0]&2 == 0 {
		t.Fatalf("MAC flags = %#x", mac[0])
	}
}

func TestGenerateRandomMACReaderError(t *testing.T) {
	_, err := generateRandomMAC(errorReader{})
	if err == nil || !errors.Is(err, errRandom) {
		t.Fatalf("error = %v, want random reader error", err)
	}
}

var errRandom = errors.New("random failure")

type errorReader struct{}

func (errorReader) Read([]byte) (int, error) { return 0, errRandom }
