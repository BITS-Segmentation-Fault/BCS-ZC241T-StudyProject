//go:build !linux

package parent

import (
	"log"
	"sandbox/sandbox/config"
)

func Parent(cfg config.Config) int {
	log.Println("[WARN] Forking sandbox execution states requires a Linux platform host environment.")
	return 0
}
