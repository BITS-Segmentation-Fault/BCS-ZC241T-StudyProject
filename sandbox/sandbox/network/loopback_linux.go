//go:build linux

package network

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// ConfigureIsolatedLoopback enables loopback inside a newly created network
// namespace without depending on host networking executables.
func ConfigureIsolatedLoopback() error {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("open loopback control socket: %w", err)
	}
	defer unix.Close(fd)

	request, err := unix.NewIfreq("lo")
	if err != nil {
		return fmt.Errorf("create loopback interface request: %w", err)
	}
	if err := unix.IoctlIfreq(fd, unix.SIOCGIFFLAGS, request); err != nil {
		return fmt.Errorf("read loopback interface flags: %w", err)
	}
	flags := request.Uint16()
	if flags&unix.IFF_UP != 0 {
		return nil
	}
	request.SetUint16(flags | unix.IFF_UP)
	if err := unix.IoctlIfreq(fd, unix.SIOCSIFFLAGS, request); err != nil {
		return fmt.Errorf("enable loopback interface: %w", err)
	}
	return nil
}
