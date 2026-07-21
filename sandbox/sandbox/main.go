package main

import (
	"fmt"
	"os"
	"strings"

	"golang.org/x/sys/unix"
	"sandbox/sandbox/child"
	"sandbox/sandbox/parent"
)

const (
	internalChildMarker = "--internal-child"
	childReadFD         = 3
	childWriteFD        = 4
)

func main() {
	internal, publicArgs, err := splitInternalInvocation(os.Args[1:])
	if err != nil {
		fatal(err)
	}

	parsed, err := ParseArgs(publicArgs)
	if err != nil {
		fatal(err)
	}

	if internal {
		if err := validateInternalChild(); err != nil {
			fatal(err)
		}
		os.Exit(child.Child(parsed.Config, childReadFD, childWriteFD))
	}

	os.Exit(parent.Parent(parsed.Config, publicArgs))
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
	for _, fd := range []int{childReadFD, childWriteFD} {
		if _, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0); err != nil {
			return fmt.Errorf("internal child descriptor %d is unavailable: %v", fd, err)
		}
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

func withEnvironment(environment []string, key, value string) []string {
	prefix := key + "="
	updated := make([]string, 0, len(environment)+1)
	found := false
	for _, entry := range environment {
		if strings.HasPrefix(entry, prefix) {
			if !found {
				updated = append(updated, prefix+value)
				found = true
			}
			continue
		}
		updated = append(updated, entry)
	}
	if !found {
		updated = append(updated, prefix+value)
	}
	return updated
}
