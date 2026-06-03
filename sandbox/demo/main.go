package main

import (
	"fmt"
	"os"

	"sandbox/demo/parent"
	"sandbox/demo/utils"
)

func main() {
	args, err := ParseArgs(os.Args[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	utils.SetupLogging(args.Verbose)

	exitCode := parent.Parent(args.Config)
	os.Exit(exitCode)
}
