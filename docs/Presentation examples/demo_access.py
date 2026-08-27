#!/usr/bin/env python3

from pathlib import Path
import argparse
import sys


class SimpleSandbox:

    def __init__(self, allowed_directories):
        self.allowed_directories = [
            Path(directory).resolve()
            for directory in allowed_directories
        ]

    def is_allowed(self, path):
        path = Path(path).resolve()

        for directory in self.allowed_directories:
            try:
                path.relative_to(directory)
                return True
            except ValueError:
                pass

        return False

    def read_file(self, path):
        path = Path(path).resolve()

        if not self.is_allowed(path):
            raise PermissionError(
                f"Access denied: {path}"
            )

        if not path.is_file():
            raise FileNotFoundError(
                f"File not found: {path}"
            )

        return path.read_text(encoding="utf-8")


def main():
    parser = argparse.ArgumentParser(
        description="Simple filesystem sandbox demonstration"
    )

    parser.add_argument(
        "--allow",
        action="append",
        required=True,
        help="Directory that the sandbox is allowed to access"
    )

    parser.add_argument(
        "files",
        nargs="+",
        help="Files to read"
    )

    args = parser.parse_args()

    sandbox = SimpleSandbox(args.allow)

    print("Basic Python demonstration")
    print()
    print("Allowed directories:")

    for directory in sandbox.allowed_directories:
        print(f"  [ALLOW] {directory}")

    print()

    for filename in args.files:
        print(f"Attempting to read:")
        print(f"  {filename}")

        try:
            content = sandbox.read_file(filename)

            print("  Result: Access granted")
            print(f"  Content: {content.strip()}")

        except PermissionError as error:
            print("  Result: Access denied")
            print(f"  Reason: {error}")

        except Exception as error:
            print("  Result: Error")
            print(f"  Reason: {error}")

        print()


if __name__ == "__main__":
    main()
