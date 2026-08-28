#!/usr/bin/env python3

import socket


failures = 0


def expect_blocked(label, operation):
    global failures
    try:
        result = operation()
    except OSError as error:
        print(f"PASS  {label} was blocked ({error})")
        return
    failures += 1
    print(f"FAIL  {label} unexpectedly succeeded ({result!r})")


print("Isolated network namespace")
print("Interfaces reported by the kernel:")
print(open("/proc/net/dev", encoding="utf-8").read().rstrip())

expect_blocked("DNS resolution", lambda: socket.getaddrinfo("example.com", 443))


def connect():
    with socket.create_connection(("1.1.1.1", 443), timeout=2):
        return "connected"


expect_blocked("outbound TCP", connect)
raise SystemExit(1 if failures else 0)
