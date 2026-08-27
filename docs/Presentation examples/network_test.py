#!/usr/bin/env python3

import socket
import urllib.request


print("Network access demonstration")
print()

print("Attempting DNS resolution...")
try:
    address = socket.gethostbyname("example.com")
    print(f"  Result: Success")
    print(f"  example.com -> {address}")
except Exception as e:
    print("  Result: Denied")
    print(f"  Reason: {e}")

print()

print("Attempting HTTP connection...")
try:
    response = urllib.request.urlopen(
        "http://example.com",
        timeout=5
    )

    print("  Result: Success")
    print(f"  HTTP status: {response.status}")

except Exception as e:
    print("  Result: Denied")
    print(f"  Reason: {e}")

print()

print("Network interfaces:")
try:
    import subprocess

    result = subprocess.run(
        ["ip", "-brief", "link"],
        capture_output=True,
        text=True
    )

    print(result.stdout.strip())

except Exception as e:
    print(f"  Unable to inspect interfaces: {e}")
