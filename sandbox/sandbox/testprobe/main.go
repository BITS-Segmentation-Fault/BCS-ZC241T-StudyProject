package main

import (
	"fmt"
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
	cwd, _ := os.Getwd()
	netNS, _ := os.Readlink("/proc/self/ns/net")
	userNS, _ := os.Readlink("/proc/self/ns/user")
	pidNS, _ := os.Readlink("/proc/self/ns/pid")
	fmt.Printf("uid=%d gid=%d pid=%d ppid=%d cwd=%s netns=%s userns=%s pidns=%s env=%s\n", os.Getuid(), os.Getgid(), os.Getpid(), os.Getppid(), cwd, netNS, userNS, pidNS, os.Getenv("PROBE_VALUE"))
	fmt.Printf("uid_map=%s\n", normalizedProcFile("/proc/self/uid_map"))
	fmt.Printf("gid_map=%s\n", normalizedProcFile("/proc/self/gid_map"))
	fmt.Printf("setgroups=%s\n", normalizedProcFile("/proc/self/setgroups"))
	printNetworkState()
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
		if arg == "--capabilities" {
			printCapabilityStatus()
		}
		if strings.HasPrefix(arg, "--syscall=") {
			probeSyscall(strings.TrimPrefix(arg, "--syscall="))
		}
		if strings.HasPrefix(arg, "--tcp=") {
			probeTCP(strings.TrimPrefix(arg, "--tcp="))
		}
		if strings.HasPrefix(arg, "--udp=") {
			probeUDP(strings.TrimPrefix(arg, "--udp="))
		}
		if strings.HasPrefix(arg, "--dns=") {
			probeDNS(strings.TrimPrefix(arg, "--dns="))
		}
		if strings.HasPrefix(arg, "--write-bytes=") {
			probeWrite(strings.TrimPrefix(arg, "--write-bytes="))
		}
		if strings.HasPrefix(arg, "--spawn-processes=") {
			probeProcesses(strings.TrimPrefix(arg, "--spawn-processes="))
		}
	}
}

func printNetworkState() {
	interfaces, err := net.Interfaces()
	if err != nil {
		fmt.Printf("interfaces-error=%v\n", err)
		return
	}
	var names []string
	for _, iface := range interfaces {
		names = append(names, iface.Name)
	}
	sort.Strings(names)
	fmt.Printf("interfaces=%s\n", strings.Join(names, ","))
	for _, iface := range interfaces {
		addrs, err := iface.Addrs()
		if err != nil {
			fmt.Printf("ipv4-error=%s:%v\n", iface.Name, err)
			continue
		}
		for _, addr := range addrs {
			ipnet, ok := addr.(*net.IPNet)
			if ok && ipnet.IP.To4() != nil {
				fmt.Printf("ipv4=%s=%s\n", iface.Name, ipnet.String())
			}
		}
		fmt.Printf("mtu=%s=%d\n", iface.Name, iface.MTU)
		if iface.Name == "lo" {
			fmt.Printf("loopback=%s\n", map[bool]string{true: "up", false: "down"}[iface.Flags&net.FlagUp != 0])
		}
	}
	defaultRoute := "none"
	if data, err := os.ReadFile("/proc/net/route"); err == nil {
		for _, line := range strings.Split(string(data), "\n")[1:] {
			fields := strings.Fields(line)
			if len(fields) >= 3 && fields[1] == "00000000" {
				gateway, parseErr := strconv.ParseUint(fields[2], 16, 32)
				if parseErr == nil {
					value := uint32(gateway)
					defaultRoute = net.IPv4(byte(value), byte(value>>8), byte(value>>16), byte(value>>24)).String()
				}
				break
			}
		}
	}
	fmt.Printf("default-route=%s\n", defaultRoute)
	ipv6 := false
	for _, iface := range interfaces {
		addrs, _ := iface.Addrs()
		for _, addr := range addrs {
			if parsed, _, err := net.ParseCIDR(addr.String()); err == nil && parsed.To4() == nil && !parsed.IsLoopback() {
				ipv6 = true
			}
		}
	}
	fmt.Printf("ipv6=%s\n", map[bool]string{true: "present", false: "none"}[ipv6])
}

func normalizedProcFile(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Sprintf("error:%v", err)
	}
	return strings.Join(strings.Fields(string(data)), " ")
}

func printCapabilityStatus() {
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		fmt.Printf("status-error=%v\n", err)
		return
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "CapEff:") || strings.HasPrefix(line, "CapPrm:") ||
			strings.HasPrefix(line, "CapInh:") || strings.HasPrefix(line, "CapAmb:") ||
			strings.HasPrefix(line, "CapBnd:") {
			fmt.Println(line)
		}
	}
}

func probeSyscall(name string) {
	numbers := map[string]uintptr{
		"mount":  unix.SYS_MOUNT,
		"reboot": unix.SYS_REBOOT,
		"ptrace": unix.SYS_PTRACE,
		"swapon": unix.SYS_SWAPON,
		"syslog": unix.SYS_SYSLOG,
	}
	number, ok := numbers[name]
	if !ok {
		fmt.Printf("syscall-error=unknown syscall %s\n", name)
		return
	}
	_, _, errno := unix.Syscall6(number, 0, 0, 0, 0, 0, 0)
	if errno != 0 {
		fmt.Printf("syscall-error=%s\n", errno)
		return
	}
	fmt.Println("syscall-ok")
}

func probeTCP(address string) {
	connection, err := net.DialTimeout("tcp", address, 500*time.Millisecond)
	if err != nil {
		fmt.Printf("tcp-error=%v\n", err)
		return
	}
	_ = connection.Close()
	fmt.Println("tcp-ok")
}

func probeUDP(address string) {
	connection, err := net.DialTimeout("udp", address, 500*time.Millisecond)
	if err != nil {
		fmt.Printf("udp-error=%v\n", err)
		return
	}
	_, err = connection.Write([]byte("probe"))
	_ = connection.Close()
	if err != nil {
		fmt.Printf("udp-error=%v\n", err)
		return
	}
	fmt.Println("udp-ok")
}

func probeDNS(name string) {
	addresses, err := net.LookupHost(name)
	if err != nil {
		fmt.Printf("dns-error=%v\n", err)
		return
	}
	fmt.Printf("dns-ok=%s\n", strings.Join(addresses, ","))
}

func probeWrite(spec string) {
	path, sizeText, ok := strings.Cut(spec, ":")
	if !ok {
		fmt.Printf("write-error=invalid specification\n")
		return
	}
	size, err := strconv.Atoi(sizeText)
	if err != nil || size < 0 {
		fmt.Printf("write-error=invalid size\n")
		return
	}
	file, err := os.Create(path)
	if err != nil {
		fmt.Printf("write-error=%v\n", err)
		return
	}
	defer file.Close()
	_, err = file.Write(make([]byte, size))
	if err != nil {
		fmt.Printf("write-error=%v\n", err)
		return
	}
	fmt.Println("write-ok")
}

func probeProcesses(countText string) {
	count, err := strconv.Atoi(countText)
	if err != nil || count < 0 {
		fmt.Println("process-error=invalid count")
		return
	}
	children := make([]*exec.Cmd, 0, count)
	for i := 0; i < count; i++ {
		child := exec.Command(os.Args[0], "--sleep=5")
		if err := child.Start(); err != nil {
			fmt.Printf("process-error=%v\n", err)
			for _, running := range children {
				_ = running.Process.Kill()
			}
			return
		}
		children = append(children, child)
	}
	for _, child := range children {
		_ = child.Process.Kill()
		_ = child.Wait()
	}
	fmt.Println("process-ok")
}
