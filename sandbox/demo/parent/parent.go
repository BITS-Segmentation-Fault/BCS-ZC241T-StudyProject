//go:build linux

package parent

import (
	"log"
	"os"
	"syscall"

	"sandbox/demo/child"
	"sandbox/demo/common"
	"sandbox/demo/config"
	"sandbox/demo/diag"
	"sandbox/demo/idmap"
)

func Parent(cfg config.Config) int {
	hostUID := syscall.Getuid()
	hostGID := syscall.Getgid()

	log.Printf("[DEBUG] host: uid=%d,gid=%d", hostUID, hostGID)
	diag.LogIdentity("parent (host namespace)", hostUID, hostGID)

	c2pR, c2pW, _ := os.Pipe()
	p2cR, p2cW, _ := os.Pipe()

	pid, _, err := syscall.Syscall(syscall.SYS_FORK, 0, 0, 0)
	if err != 0 {
		log.Printf("[ERROR] fork failed: %v", err)
		return 1
	}

	if pid == 0 {
		c2pR.Close()
		p2cW.Close()
		rc := child.Child(cfg, p2cR.Fd(), c2pW.Fd(), hostUID, hostGID)
		os.Exit(rc)
	}

	c2pW.Close()
	p2cR.Close()

	buf := make([]byte, 1)
	if _, err := c2pR.Read(buf); err != nil || buf[0] != common.ReadyByte {
		log.Println("[ERROR] child did not signal readiness; aborting")
		_ = syscall.Kill(int(pid), syscall.SIGKILL)
		return 1
	}

	log.Printf("[DEBUG] child ready; writing uid/gid maps for pid=%d", pid)
	if err := idmap.WriteIDMaps(int(pid), hostUID, hostGID); err != nil {
		log.Printf("[ERROR] failed to write uid/gid maps: %v", err)
		_ = syscall.Kill(int(pid), syscall.SIGKILL)
		return 1
	}

	_, _ = p2cW.Write([]byte{common.AckByte})
	p2cW.Close()

	var status syscall.WaitStatus
	_, errWait := syscall.Waitpid(int(pid), &status, 0)
	if errWait != nil {
		return 1
	}

	log.Printf("[DEBUG] child exit code: %d", status.ExitStatus())
	return status.ExitStatus()
}
