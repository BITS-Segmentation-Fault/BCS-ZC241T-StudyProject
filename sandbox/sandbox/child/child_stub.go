//go:build !linux

package child

import (
	"log"
	"sandbox/sandbox/config"
)

func Child(cfg config.Config, p2cR, c2pW int) int {
	log.Println("[WARN] Container namespaces are only supported natively on Linux platforms.")
	return 0
}
