package main

import (
	"fmt"
	"os"

	"sandbox/demo/child"
	"sandbox/demo/parent"
)

func main() {
	// The internal -child flag is prepended by parent.go when re-execing.
	isChild := false
	var filtered []string
	for _, arg := range os.Args[1:] {
		if arg == "-child" {
			isChild = true
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
		rc := child.Child(cfg, 0, 0, 0, 0)
		os.Exit(rc)
	} else {
		rc := parent.Parent(cfg)
		os.Exit(rc)
	}
}
