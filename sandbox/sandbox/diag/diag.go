package diag

import (
	"log"
	"syscall"

	"sandbox/demo/fs"
	"sandbox/demo/utils"
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

	uidMap := fs.ReadText("/proc/self/uid_map")
	gidMap := fs.ReadText("/proc/self/gid_map")
	log.Printf("[DEBUG] /proc/self/uid_map:\n%s", uidMap)
	log.Printf("[DEBUG] /proc/self/gid_map:\n%s", gidMap)

	statusText := fs.ReadText("/proc/self/status")
	matchedLines := utils.SelectLinesWithPrefix(statusText, StatusKeys)
	for _, line := range matchedLines {
		log.Printf("[DEBUG] %s", line)
	}
}
