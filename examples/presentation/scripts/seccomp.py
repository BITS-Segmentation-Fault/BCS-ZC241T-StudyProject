#!/usr/bin/env python3

import ctypes
import signal


PTRACE_TRACEME = 0
trapped = False


def handle_sigsys(_signum, _frame):
    global trapped
    trapped = True


signal.signal(signal.SIGSYS, handle_sigsys)
libc = ctypes.CDLL(None, use_errno=True)
libc.ptrace.argtypes = [ctypes.c_ulong, ctypes.c_ulong, ctypes.c_void_p, ctypes.c_void_p]
libc.ptrace.restype = ctypes.c_long

print("Seccomp syscall interception", flush=True)
ctypes.set_errno(0)
result = libc.ptrace(PTRACE_TRACEME, 0, None, None)
error = ctypes.get_errno()

if trapped:
    print(f"PASS  ptrace produced SIGSYS (result={result}, errno={error})")
    raise SystemExit(0)

print(f"FAIL  ptrace result={result}, errno={error}, SIGSYS observed={trapped}")
raise SystemExit(1)
