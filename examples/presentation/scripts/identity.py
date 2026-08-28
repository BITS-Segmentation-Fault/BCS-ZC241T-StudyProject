#!/usr/bin/env python3

import os


def status_fields():
    wanted = {"CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb", "NoNewPrivs"}
    fields = {}
    with open("/proc/self/status", encoding="utf-8") as status:
        for line in status:
            name, separator, value = line.partition(":")
            if separator and name in wanted:
                fields[name] = value.strip()
    return fields


print("Namespaced identity and capability policy")
print(f"uid={os.getuid()} euid={os.geteuid()} gid={os.getgid()} egid={os.getegid()}")
print("uid_map:", open("/proc/self/uid_map", encoding="utf-8").read().strip())
print("gid_map:", open("/proc/self/gid_map", encoding="utf-8").read().strip())

fields = status_fields()
for name in sorted(fields):
    print(f"{name}={fields[name]}")

failures = 0
capability_fields = ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb")
if all(int(fields.get(name, "1"), 16) == 0 for name in capability_fields):
    print(
        "PASS  inheritable, permitted, effective, bounding, and ambient "
        "capabilities are empty"
    )
else:
    failures += 1
    print("FAIL  at least one capability set is not empty")

if fields.get("NoNewPrivs") == "1":
    print("PASS  no_new_privs is enabled")
else:
    failures += 1
    print("FAIL  no_new_privs is not enabled")

try:
    os.setuid(1)
except OSError as error:
    print(f"PASS  changing to an unmapped identity was denied ({error})")
else:
    failures += 1
    print("FAIL  changing to an unmapped identity succeeded")

raise SystemExit(1 if failures else 0)
