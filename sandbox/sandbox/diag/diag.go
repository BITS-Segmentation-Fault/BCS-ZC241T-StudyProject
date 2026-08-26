package diag

import (
	"errors"
	"fmt"
	"log"
	"os"
	"syscall"

	"sandbox/sandbox/utils"
)

var StatusKeys = []string{"Uid:", "Gid:", "Groups:", "CapEff:", "NSpid:"}

func LogIdentity(label string, hostUID, hostGID int) {
	uid := syscall.Getuid()
	euid := syscall.Geteuid()
	gid := syscall.Getgid()
	egid := syscall.Getegid()

	log.Printf("[DEBUG] === %s ===", label)
	log.Printf("[DEBUG] host: uid=%d,gid=%d", hostUID, hostGID)
	log.Printf("[DEBUG] self: uid=%d,euid=%d,gid=%d,egid=%d", uid, euid, gid, egid)

	uidMap := ReadText("/proc/self/uid_map")
	gidMap := ReadText("/proc/self/gid_map")
	log.Printf("[DEBUG] /proc/self/uid_map:\n%s", uidMap)
	log.Printf("[DEBUG] /proc/self/gid_map:\n%s", gidMap)

	statusText := ReadText("/proc/self/status")
	matchedLines := utils.SelectLinesWithPrefix(statusText, StatusKeys)
	for _, line := range matchedLines {
		log.Printf("[DEBUG] %s", line)
	}
}

func ReadText(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "<missing>"
		}
		if errors.Is(err, os.ErrPermission) {
			return fmt.Sprintf("<permission denied: %v>", err)
		}
		return fmt.Sprintf("<error: %v>", err)
	}
	return string(data)
}
