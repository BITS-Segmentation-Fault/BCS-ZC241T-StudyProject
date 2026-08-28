#!/usr/bin/env python3

from pathlib import Path


failures = 0


def passed(message):
    print(f"PASS  {message}")


def failed(message):
    global failures
    failures += 1
    print(f"FAIL  {message}")


shared = Path("/shared/allowed.txt")
print("Filesystem confinement")
print(f"READ  {shared}: {shared.read_text(encoding='utf-8').strip()}")

try:
    shared.write_text("changed\n", encoding="utf-8")
except OSError as error:
    passed(f"read-only bind rejected a write ({error.strerror})")
else:
    failed("read-only bind accepted a write")

try:
    Path("/created-by-payload").write_text("unexpected\n", encoding="utf-8")
except OSError as error:
    passed(f"read-only root rejected a new file ({error.strerror})")
else:
    failed("read-only root accepted a new file")

hidden = Path("/host-secret.txt")
if hidden.exists():
    failed(f"unexpected host path is visible: {hidden}")
else:
    passed("an unmounted host path is absent")

raise SystemExit(1 if failures else 0)
