import ctypes
import sys
import os

# Linux kernel constants for Secure Computing
PR_SET_SECCOMP = 22
SECCOMP_MODE_STRICT = 1

print("1. Unrestricted state: Executing 'getpid' syscall...")
print(f"   Success. Current PID: {os.getpid()}\n")

print("2. Activating SECCOMP Strict Mode...")
sys.stdout.flush() # Flush buffer before we lose access to I/O syscalls

libc = ctypes.CDLL("libc.so.6")
libc.prctl(PR_SET_SECCOMP, SECCOMP_MODE_STRICT)

print("3. Restricted state: Attempting 'getpid' syscall again...")
sys.stdout.flush()

# This line requires the 'getpid' syscall, which is now illegal.
# The kernel will intercept this and immediately terminate the process.
os.getpid()

print("4. You will never see this message.")
