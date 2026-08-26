package main

import (
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	if len(args) == 0 {
		return usageError("missing mode")
	}
	switch args[0] {
	case "inspect":
		return inspect(args[1:])
	case "environment":
		if len(args) != 2 {
			return usageError("environment requires a variable name")
		}
		fmt.Printf("environment=%s=%s\n", args[1], os.Getenv(args[1]))
		return 0
	case "read":
		if len(args) != 2 {
			return usageError("read requires a path")
		}
		return readFile(args[1])
	case "capabilities":
		if len(args) != 1 {
			return usageError("capabilities takes no arguments")
		}
		return capabilities()
	case "syscall":
		if len(args) != 2 {
			return usageError("syscall requires a name")
		}
		return probeSyscall(args[1])
	case "append":
		if len(args) != 3 {
			return usageError("append requires a path and text")
		}
		return appendFile(args[1], args[2])
	case "write-size":
		if len(args) != 3 {
			return usageError("write-size requires a path and byte count")
		}
		return writeSize(args[1], args[2])
	case "spawn":
		if len(args) != 2 {
			return usageError("spawn requires a count")
		}
		return spawn(args[1])
	case "sleep":
		if len(args) != 2 {
			return usageError("sleep requires a duration")
		}
		return sleepFor(args[1])
	case "exit":
		if len(args) != 2 {
			return usageError("exit requires a code")
		}
		return exitWith(args[1])
	default:
		return usageError("unknown mode " + args[0])
	}
}

func usageError(message string) int {
	fmt.Fprintf(os.Stderr, "probe: %s\n", message)
	return 2
}

func inspect(args []string) int {
	if len(args) > 1 {
		return usageError("inspect accepts an optional duration")
	}
	var duration time.Duration
	if len(args) == 1 {
		var err error
		duration, err = time.ParseDuration(args[0])
		if err != nil || duration < 0 {
			return usageError("invalid inspect duration")
		}
	}
	cwd, err := os.Getwd()
	if err != nil {
		return inspectError("getwd", err)
	}
	netNS, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		return inspectError("network namespace", err)
	}
	userNS, err := os.Readlink("/proc/self/ns/user")
	if err != nil {
		return inspectError("user namespace", err)
	}
	pidNS, err := os.Readlink("/proc/self/ns/pid")
	if err != nil {
		return inspectError("PID namespace", err)
	}
	fmt.Printf("identity=uid=%d gid=%d pid=%d ppid=%d cwd=%s\n", os.Getuid(), os.Getgid(), os.Getpid(), os.Getppid(), cwd)
	fmt.Printf("netns=%s\n", netNS)
	fmt.Printf("userns=%s\n", userNS)
	fmt.Printf("pidns=%s\n", pidNS)
	for _, file := range []struct {
		name string
		path string
	}{
		{name: "uid_map", path: "/proc/self/uid_map"},
		{name: "gid_map", path: "/proc/self/gid_map"},
		{name: "setgroups", path: "/proc/self/setgroups"},
	} {
		value, err := normalizedProcFile(file.path)
		if err != nil {
			return inspectError(file.name, err)
		}
		fmt.Printf("%s=%s\n", file.name, value)
	}
	if err := printNetworkState(); err != nil {
		return inspectError("network inspection", err)
	}
	fmt.Println("ready")
	if len(args) == 1 {
		time.Sleep(duration)
	}
	return 0
}

func inspectError(kind string, err error) int {
	fmt.Fprintf(os.Stderr, "inspect-error=%s: %v\n", kind, err)
	return 1
}

func readFile(path string) int {
	data, err := os.ReadFile(path)
	if err != nil {
		fmt.Printf("read-error=%v\n", err)
		return 0
	}
	fmt.Printf("read=%s\n", data)
	return 0
}

func capabilities() int {
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		fmt.Printf("status-error=%v\n", err)
		return 1
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "CapEff:") || strings.HasPrefix(line, "CapPrm:") ||
			strings.HasPrefix(line, "CapInh:") || strings.HasPrefix(line, "CapAmb:") ||
			strings.HasPrefix(line, "CapBnd:") {
			fmt.Println(line)
		}
	}
	return 0
}

func probeSyscall(name string) int {
	numbers := map[string]uintptr{
		"mount":  unix.SYS_MOUNT,
		"reboot": unix.SYS_REBOOT,
		"ptrace": unix.SYS_PTRACE,
		"swapon": unix.SYS_SWAPON,
		"syslog": unix.SYS_SYSLOG,
	}
	number, ok := numbers[name]
	if !ok {
		return usageError("unknown syscall " + name)
	}
	fmt.Println("syscall-ready")
	_, _, errno := unix.Syscall6(number, 0, 0, 0, 0, 0, 0)
	if errno != 0 {
		fmt.Printf("syscall-error=%s\n", errno)
		return 0
	}
	fmt.Println("syscall-ok")
	return 0
}

func appendFile(path, text string) int {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		fmt.Printf("append-error=%v\n", err)
		return 0
	}
	n, err := file.WriteString(text)
	if err != nil {
		_ = file.Close()
		fmt.Printf("append-error=%v\n", err)
		return 0
	}
	if n != len(text) {
		_ = file.Close()
		fmt.Printf("append-error=%v\n", io.ErrShortWrite)
		return 0
	}
	if err := file.Close(); err != nil {
		fmt.Printf("append-error=%v\n", err)
		return 0
	}
	fmt.Println("append-ok")
	return 0
}

func writeSize(path, countText string) int {
	count, err := strconv.ParseUint(countText, 10, 64)
	if err != nil || count > uint64(^uint(0)>>1) {
		return usageError("invalid byte count")
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		fmt.Printf("write-error=%v\n", err)
		return 0
	}
	buffer := make([]byte, 32*1024)
	remaining := count
	for remaining > 0 {
		chunk := uint64(len(buffer))
		if remaining < chunk {
			chunk = remaining
		}
		written := 0
		for written < int(chunk) {
			n, err := file.Write(buffer[written:int(chunk)])
			if err != nil {
				_ = file.Close()
				fmt.Printf("write-error=%v\n", err)
				return 0
			}
			if n == 0 {
				_ = file.Close()
				fmt.Printf("write-error=%v\n", io.ErrShortWrite)
				return 0
			}
			written += n
		}
		remaining -= chunk
	}
	if err := file.Close(); err != nil {
		fmt.Printf("write-error=%v\n", err)
		return 0
	}
	fmt.Println("write-ok")
	return 0
}

func spawn(countText string) int {
	count, err := strconv.Atoi(countText)
	if err != nil || count < 0 {
		return usageError("invalid child count")
	}
	children := make([]*exec.Cmd, 0, count)
	cleanup := func() {
		for _, child := range children {
			if child.Process != nil {
				_ = child.Process.Kill()
			}
		}
		for _, child := range children {
			_ = child.Wait()
		}
	}
	for i := 0; i < count; i++ {
		child := exec.Command(os.Args[0], "sleep", "5s")
		if err := child.Start(); err != nil {
			cleanup()
			fmt.Printf("process-error=%v\n", err)
			return 0
		}
		children = append(children, child)
	}
	cleanup()
	fmt.Println("spawn-ok")
	return 0
}

func sleepFor(value string) int {
	duration, err := time.ParseDuration(value)
	if err != nil || duration < 0 {
		return usageError("invalid sleep duration")
	}
	fmt.Println("ready")
	time.Sleep(duration)
	return 0
}

func exitWith(value string) int {
	code, err := strconv.Atoi(value)
	if err != nil || code < 0 || code > 255 {
		return usageError("invalid exit code")
	}
	return code
}

type interfaceState struct {
	name  string
	mtu   int
	up    bool
	addrs []string
}

func printNetworkState() error {
	interfaces, err := net.Interfaces()
	if err != nil {
		return err
	}
	states := make([]interfaceState, 0, len(interfaces))
	for _, iface := range interfaces {
		state := interfaceState{name: iface.Name, mtu: iface.MTU, up: iface.Flags&net.FlagUp != 0}
		addresses, err := iface.Addrs()
		if err != nil {
			return fmt.Errorf("addresses for %s: %w", iface.Name, err)
		}
		for _, address := range addresses {
			state.addrs = append(state.addrs, address.String())
		}
		sort.Strings(state.addrs)
		states = append(states, state)
	}
	sort.Slice(states, func(i, j int) bool { return states[i].name < states[j].name })
	names := make([]string, 0, len(states))
	for _, state := range states {
		names = append(names, state.name)
	}
	fmt.Printf("interfaces=%s\n", strings.Join(names, ","))
	for _, state := range states {
		for _, address := range state.addrs {
			if parsed, _, err := net.ParseCIDR(address); err == nil && parsed.To4() != nil {
				fmt.Printf("ipv4=%s=%s\n", state.name, address)
			}
		}
		fmt.Printf("mtu=%s=%d\n", state.name, state.mtu)
		if state.name == "lo" {
			if state.up {
				fmt.Println("loopback=up")
			} else {
				fmt.Println("loopback=down")
			}
		}
	}
	defaultRoute, err := readDefaultRoute()
	if err != nil {
		return err
	}
	fmt.Printf("default-route=%s\n", defaultRoute)
	ipv6 := false
	for _, state := range states {
		for _, address := range state.addrs {
			parsed, _, err := net.ParseCIDR(address)
			if err != nil {
				return fmt.Errorf("parse address %s: %w", address, err)
			}
			if state.name != "lo" && parsed.To4() == nil {
				ipv6 = true
			}
		}
	}
	if ipv6 {
		fmt.Println("ipv6=present")
	} else {
		fmt.Println("ipv6=none")
	}
	return nil
}

func readDefaultRoute() (string, error) {
	data, err := os.ReadFile("/proc/net/route")
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(data), "\n")[1:] {
		fields := strings.Fields(line)
		if len(fields) < 3 || fields[1] != "00000000" {
			continue
		}
		gateway, err := strconv.ParseUint(fields[2], 16, 32)
		if err != nil {
			return "", fmt.Errorf("parse default gateway: %w", err)
		}
		value := uint32(gateway)
		return net.IPv4(byte(value), byte(value>>8), byte(value>>16), byte(value>>24)).String(), nil
	}
	return "none", nil
}

func normalizedProcFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return strings.Join(strings.Fields(string(data)), " "), nil
}
