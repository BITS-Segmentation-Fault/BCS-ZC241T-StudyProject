//go:build linux && !amd64 && !arm64

package security

const auditArchitecture uint32 = 0
const x32ABIBit uint32 = 0

var syscallNameToNumber = map[string]uint32{}
