//go:build linux

package parent

import (
	"log"
	"os"
	"os/exec"
	"os/signal"
	"syscall"

	"sandbox/demo/config"
	"sandbox/demo/resources"

	"golang.org/x/sys/unix"
)

func Parent(cfg config.Config) int {
	// Pre-flight Verification
	if os.Geteuid() != 0 {
		log.Println("[PRE-FLIGHT ERROR] Sandbox must be executed with root privileges (sudo).")
		return 1
	}
	log.Println("[DEBUG] Pre-flight verification passed: Running as administrative root.")

	cmd := exec.Command("/proc/self/exe", append([]string{"-child"}, os.Args[1:]...)...)

	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	// HARDENING & ISOLATION
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags: syscall.CLONE_NEWUSER | syscall.CLONE_NEWPID | syscall.CLONE_NEWNS | syscall.CLONE_NEWUTS,
		UidMappings: []syscall.SysProcIDMap{
			{ContainerID: 0, HostID: os.Getuid(), Size: 1},
		},
		GidMappings: []syscall.SysProcIDMap{
			{ContainerID: 0, HostID: os.Getgid(), Size: 1},
		},
	}

	// Start the child safely
	if err := cmd.Start(); err != nil {
		log.Printf("[CRITICAL] Failed to spawn container process safely: %v", err)
		return 1
	}

	pid := cmd.Process.Pid
	log.Printf("[DEBUG] Container initialized safely. Child Tracking PID: %d", pid)

	// Set up lifecycle signal monitoring
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-sigChan
		log.Printf("[DEBUG] Parent caught signal: %v. Cleaning up child PID %d...", sig, pid)
		_ = syscall.Kill(pid, syscall.SIGKILL)
		os.Exit(1)
	}()

	var expansionCount int

	// Monitor Loop
	for {
		var status unix.WaitStatus
		_, errWait := unix.Wait4(pid, &status, 0, nil)
		if errWait != nil {
			log.Printf("[ERROR] Failure occurred during process wait state collection: %v", errWait)
			return 1
		}

		if status.Exited() {
			log.Printf("[DEBUG] Child execution loop finished cleanly. Exit code: %d", status.ExitStatus())
			return status.ExitStatus()
		}

		if status.Signaled() {
			sig := status.Signal()

			switch sig {
			case unix.SIGXFSZ:
				expanded, newCount := resources.EvaluateStorageExpansion(pid, cfg.Storage, expansionCount)
				if expanded {
					expansionCount = newCount
					continue
				}
				log.Println("[CRITICAL STORAGE ALERT] Container sandbox execution halted, exceeded limit.")
				return 1

			case unix.SIGSYS:
				log.Println("------------------------------------------------------------------------")
				log.Println("[CRITICAL SECURITY ALERT] Container sandbox execution terminated forcefully")
				log.Println("[CRITICAL SECURITY ALERT] Cause: Forbidden system call interface requested (Seccomp violation).")
				log.Println("[CRITICAL SECURITY ALERT] Mitigation: Execution halted immediately. Host protected.")
				log.Println("------------------------------------------------------------------------")
				return 1

			default:
				log.Printf("[DEBUG] Child terminated via unhandled signal: %v", sig)
				return 1
			}
		}
	}
}
