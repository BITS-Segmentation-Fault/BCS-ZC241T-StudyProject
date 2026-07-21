package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

func main() {
	cwd, _ := os.Getwd()
	netNS, _ := os.Readlink("/proc/self/ns/net")
	userNS, _ := os.Readlink("/proc/self/ns/user")
	pidNS, _ := os.Readlink("/proc/self/ns/pid")
	fmt.Printf("uid=%d gid=%d pid=%d ppid=%d cwd=%s netns=%s userns=%s pidns=%s env=%s\n", os.Getuid(), os.Getgid(), os.Getpid(), os.Getppid(), cwd, netNS, userNS, pidNS, os.Getenv("PROBE_VALUE"))
	for _, arg := range os.Args[1:] {
		if strings.HasPrefix(arg, "--exit=") {
			code, _ := strconv.Atoi(strings.TrimPrefix(arg, "--exit="))
			os.Exit(code)
		}
		if strings.HasPrefix(arg, "--sleep=") {
			seconds, _ := strconv.Atoi(strings.TrimPrefix(arg, "--sleep="))
			time.Sleep(time.Duration(seconds) * time.Second)
		}
		if strings.HasPrefix(arg, "--read=") {
			path := strings.TrimPrefix(arg, "--read=")
			data, err := os.ReadFile(path)
			if err != nil {
				fmt.Printf("read-error=%v\n", err)
				continue
			}
			fmt.Printf("read=%s\n", data)
		}
	}
}
