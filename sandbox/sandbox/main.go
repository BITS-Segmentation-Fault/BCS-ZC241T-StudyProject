package main

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"sandbox/sandbox/child"
	"sandbox/sandbox/parent"
)

func main() {
	isChild := false
	childReadFd := 0
	childWriteFd := 0
	var filtered []string
	for _, arg := range os.Args[1:] {
		if arg == "-child" {
			isChild = true
		} else if strings.HasPrefix(arg, "--child-read-fd=") {
			val := strings.TrimPrefix(arg, "--child-read-fd=")
			if n, err := strconv.Atoi(val); err == nil {
				childReadFd = n
			}
		} else if strings.HasPrefix(arg, "--child-write-fd=") {
			val := strings.TrimPrefix(arg, "--child-write-fd=")
			if n, err := strconv.Atoi(val); err == nil {
				childWriteFd = n
			}
		} else {
			filtered = append(filtered, arg)
		}
	}

	parsed, err := ParseArgs(filtered)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	cfg := parsed.Config

	if isChild {
		// FIX: Re-exec the child process with GODEBUG=pidfd=0 and GOEXPERIMENT=none
		// to prevent the Go runtime from attempting to use features incompatible 
		// with restricted network namespaces.
		if os.Getenv("GODEBUG") != "pidfd=0" {
			cmd := exec.Command("/proc/self/exe", os.Args[1:]...)
			cmd.Env = append(os.Environ(), "GODEBUG=pidfd=0", "GOEXPERIMENT=none")
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			cmd.Stdin = os.Stdin

			// This replaces the current process with a new one that has the correct env
			err := cmd.Run()
			if err != nil {
				fmt.Fprintf(os.Stderr, "Re-exec failed: %v\n", err)
				os.Exit(1)
			}
			os.Exit(0)
		}

		// If we are here, we are already re-exec'd with the right envs
		rc := child.Child(cfg, uintptr(childReadFd), uintptr(childWriteFd), 0, 0)
		os.Exit(rc)
	} else {
		rc := parent.Parent(cfg)
		os.Exit(rc)
	}
}
