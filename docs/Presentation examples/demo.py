import subprocess

print("Attempting to acquire root privileges...")
try:
    result = subprocess.run(
        ["sudo", "-n", "whoami"],
        capture_output=True,
        text=True
    )

    if result.returncode == 0:
        print(f"Success, running as: {result.stdout.strip()}")
    else:
        print(f"Failed to acquire root.\nError output: {result.stderr.strip()}")
except FileNotFoundError:
    print("Error: sudo command not found.")
