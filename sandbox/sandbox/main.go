package main

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
	"sandbox/sandbox/child"
	"sandbox/sandbox/parent"
)

const (
	internalChildMarker = "--internal-child"
	childReadFD         = 3
)

func main() {
	internal, publicArgs, err := splitInternalInvocation(os.Args[1:])
	if err != nil {
		fatal(err)
	}

	if internal {
		if err := validateInternalChild(); err != nil {
			fatal(err)
		}
		os.Exit(child.Child(childReadFD))
	}

	cfg, err := ParseArgs(publicArgs)
	if err != nil {
		fatal(err)
	}
	os.Exit(parent.Parent(cfg))
}

func splitInternalInvocation(argv []string) (bool, []string, error) {
	if len(argv) > 0 && argv[0] == internalChildMarker {
		return true, append([]string(nil), argv[1:]...), nil
	}
	for _, arg := range argv {
		if arg == internalChildMarker {
			return false, nil, fmt.Errorf("internal child marker must be the first argument")
		}
	}
	return false, append([]string(nil), argv...), nil
}

func validateInternalChild() error {
	if os.Getpid() != 1 {
		return fmt.Errorf("internal child invocation requires PID 1 in a new PID namespace")
	}
	if _, err := unix.FcntlInt(uintptr(childReadFD), unix.F_GETFD, 0); err != nil {
		return fmt.Errorf("internal child descriptor %d is unavailable: %v", childReadFD, err)
	}
	return nil
}

func fatal(err error) {
	if err == nil {
		return
	}
	fmt.Fprintf(os.Stderr, "Error: %v\n", err)
	os.Exit(1)
}
