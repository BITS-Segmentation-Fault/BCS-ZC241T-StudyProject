//go:build !linux

package parent

import (
	"log"
	"sandbox/sandbox/config"
)

func Parent(cfg config.Config, _ []string) int {
	log.Println("[WARN] Forking sandbox execution states requires a Linux platform host environment.")
	return 0
}
