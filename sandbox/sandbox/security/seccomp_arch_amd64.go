//go:build linux && amd64

package security

import "golang.org/x/sys/unix"

const auditArchitecture uint32 = 0xc000003e
const x32ABIBit uint32 = 1 << 30

var syscallNameToNumber = map[string]uint32{
	"reboot":            uint32(unix.SYS_REBOOT),
	"mount":             uint32(unix.SYS_MOUNT),
	"ptrace":            uint32(unix.SYS_PTRACE),
	"swapon":            uint32(unix.SYS_SWAPON),
	"syslog":            uint32(unix.SYS_SYSLOG),
	"init_module":       uint32(unix.SYS_INIT_MODULE),
	"finit_module":      uint32(unix.SYS_FINIT_MODULE),
	"delete_module":     uint32(unix.SYS_DELETE_MODULE),
	"iopl":              uint32(unix.SYS_IOPL),
	"ioperm":            uint32(unix.SYS_IOPERM),
	"kcmp":              uint32(unix.SYS_KCMP),
	"process_vm_readv":  uint32(unix.SYS_PROCESS_VM_READV),
	"process_vm_writev": uint32(unix.SYS_PROCESS_VM_WRITEV),
	"nfsservctl":        uint32(unix.SYS_NFSSERVCTL),
	"create_module":     uint32(unix.SYS_CREATE_MODULE),
}
