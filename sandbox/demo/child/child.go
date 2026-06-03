//go:build linux

package child

import (
	"log"
	"os"
	"syscall"

	"sandbox/demo/common"
	"sandbox/demo/config"
	"sandbox/demo/diag"
	"sandbox/demo/network"
	"sandbox/demo/utils"
)

func Child(cfg config.Config, p2cR, c2pW uintptr, hostUID, hostGID int) int {
	_ = syscall.Setgroups([]int{})

	log.Println("[DEBUG] child starting before unshare()")
	diag.LogIdentity("child (before unshare)", hostUID, hostGID)

	flags := syscall.CLONE_NEWUSER
	if cfg.NetworkMode != network.Host {
		flags |= syscall.CLONE_NEWNET
	}

	if err := syscall.Unshare(flags); err != nil {
		log.Printf("[ERROR] unshare fail: %v", err)
		return 1
	}
	log.Printf("[DEBUG] unshare success (flags=%d)", flags)

	c2pWriter := os.NewFile(c2pW, "c2p_w")
	p2cReader := os.NewFile(p2cR, "p2c_r")

	_, _ = c2pWriter.Write([]byte{common.ReadyByte})
	c2pWriter.Close()
	log.Println("[DEBUG] signaled ready to parent")

	ackBuf := make([]byte, 1)
	if _, err := p2cReader.Read(ackBuf); err != nil || ackBuf[0] != common.AckByte {
		log.Println("[ERROR] did not receive mapping ACK from parent; aborting")
		return 1
	}
	p2cReader.Close()

	_ = syscall.Setresgid(0, 0, 0)
	_ = syscall.Setresuid(0, 0, 0)

	log.Println("[DEBUG] child is now root inside the user namespace")
	diag.LogIdentity("child (after mapping + setuid(0))", hostUID, hostGID)

	log.Printf("[DEBUG] exec: %v", cfg.Command)
	utils.FlushLogs()

	env := os.Environ()
	if err := syscall.Exec(cfg.Command[0], cfg.Command, env); err != nil {
		log.Printf("[ERROR] failed to execute target program: %v", err)
		return 1
	}

	return 0
}
