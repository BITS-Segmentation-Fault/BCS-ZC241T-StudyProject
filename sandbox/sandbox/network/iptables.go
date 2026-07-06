//go:build linux

package network

import (
	"fmt"
	"log"
	"os/exec"
)

func SetupNAT(cfg BridgeConfig) error {
	log.Printf("[NETWORK] Configuring NAT masquerade for %s", cfg.Subnet)
	cmd := exec.Command("iptables", "-t", "nat", "-A", "POSTROUTING",
		"-s", cfg.Subnet, "!", "-o", cfg.BridgeName, "-j", "MASQUERADE")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to add NAT masquerade rule: %v\n%s", err, string(out))
	}
	log.Printf("[NETWORK] NAT masquerade configured for %s", cfg.Subnet)
	return nil
}

func TeardownNAT(cfg BridgeConfig) error {
	log.Printf("[NETWORK] Removing NAT masquerade for %s", cfg.Subnet)
	cmd := exec.Command("iptables", "-t", "nat", "-D", "POSTROUTING",
		"-s", cfg.Subnet, "!", "-o", cfg.BridgeName, "-j", "MASQUERADE")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to remove NAT masquerade rule: %v\n%s", err, string(out))
	}
	log.Printf("[NETWORK] NAT masquerade removed")
	return nil
}

func BlockHostMetadata() error {
	log.Printf("[NETWORK] Blocking host metadata access (169.254.169.254)...")
	blockIP := func(ip, comment string) error {
		cmd := exec.Command("iptables", "-A", "FORWARD",
			"-d", ip, "-j", "DROP")
		out, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("failed to block %s (%s): %v\n%s", ip, comment, err, string(out))
		}
		return nil
	}
	if err := blockIP("169.254.169.254", "cloud metadata"); err != nil {
		return err
	}
	if err := blockIP("169.254.0.0/16", "link-local"); err != nil {
		return err
	}
	log.Printf("[NETWORK] Host metadata and link-local access blocked")
	return nil
}

func UnblockHostMetadata() error {
	log.Printf("[NETWORK] Removing host metadata access blocks...")
	unblockIP := func(ip string) error {
		cmd := exec.Command("iptables", "-D", "FORWARD",
			"-d", ip, "-j", "DROP")
		out, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("failed to unblock %s: %v\n%s", ip, err, string(out))
		}
		return nil
	}
	_ = unblockIP("169.254.169.254")
	_ = unblockIP("169.254.0.0/16")
	log.Printf("[NETWORK] Host metadata access blocks removed")
	return nil
}
