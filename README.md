# Linux Sandbox User Manual

Linux applications normally execute with the same permissions as the user who launched them. A command-line application can therefore access the user's files, environment, and network unless those resources are explicitly restricted.

This project provides a lightweight, rootless sandbox runtime for Linux command-line and headless applications. A user can launch a command directly using command-line options or provide a readable, declarative YAML policy. The restrictive defaults provide isolated networking, a read-only managed root filesystem, a seccomp denylist and removal of all Linux capabilities. More permissive behavior, such as host networking or writable host files, must be explicitly configured.

This sandbox does not require a background daemon, made a setuid-root executable, or privileged access (normally). Only bridge mode requires extra privileges due to its nature.

## What the sandbox offers

- An isolated process, mount, identity and hostname environment
- No network access by default
- A read-only root filesystem by default
- Explicit, read-only host file sharing by default
- Capability removal and configurable seccomp filtering
- Verified managed and remote root filesystems
- Optional interactive terminal support
- Optional CPU, memory, process and per-file size limits
- Linux `amd64` and `arm64` support

This is a Linux process sandbox, not a virtual machine. It shares the host kernel and depends on the host allowing unprivileged user namespaces.

## Requirements

- Linux on `amd64` or `arm64`
- Go 1.26.3 or later to build from source
- Unprivileged user namespaces enabled for rootless execution

Bazel 9.1.0 is optional and is only needed for repository-wide builds, tests and packaging.

## Build

```bash
cd sandbox/sandbox
go build -o sandbox .
```

The executable is created in the current directory with the name `sandbox`.

Optionally install it in `/usr/local/bin/` (requires root, but sandbox program does not require root):

```bash
sudo install -m 0755 sandbox /usr/local/bin/sandbox
```

## Quick start

Run a command with the default isolated policy:

```bash
sandbox -- /bin/echo "hello from the sandbox"
```

If no root filesystem is configured, the first run downloads a pinned Alpine minirootfs, verifies its SHA-256 digest and caches it. Later runs reuse the cache.

Run an interactive shell:

```bash
sandbox --interactive -- /bin/sh -i
```

Run a repeatable YAML policy:

```bash
sandbox --config ./sandbox.yaml
```

Options must appear before the payload command. Use `--` to separate sandbox options from payload arguments.

## Command-line reference

The sandbox has two command forms:

```text
sandbox [OPTIONS] -- COMMAND [ARGUMENT...]
sandbox --config FILE [OVERRIDE OPTIONS]
```

In the first form, `COMMAND` is required. In the second form, the YAML file must contain a `command` field (note that a second command cannot be supplied on the command line).

All options must appear before the payload command. Use `--` to end sandbox option parsing, especially when the payload has arguments beginning with `-`.

| Option | Purpose | Default |
|---|---|---|
| `--config FILE` | Load one declarative YAML policy file. | No file |
| `--network-mode MODE` | Select `none`, `host`, or `bridge` networking. | `none` |
| `--bridge-subnet CIDR` | Set the canonical IPv4 subnet used by bridge mode. | `10.0.100.0/24` |
| `--bridge-gateway ADDRESS` | Set the host-side gateway address within the bridge subnet. | `10.0.100.1` |
| `--bridge-container-ip ADDRESS` | Set the payload-side address within the bridge subnet. | `10.0.100.2` |
| `--env-whitelist NAME[,NAME...]` | Copy only the named variables from the host environment. | Empty |
| `--file-size-limit MIB` | Limit the size of each file created or extended by the payload. | `100` MiB |
| `--interactive`, `-i` | Allocate an interactive pseudo-terminal. | `false` |
| `--` | End sandbox option parsing. | - |

### `--config FILE`

Loads a YAML configuration. Unknown fields, trailing YAML documents and configuration files larger than 1 MiB are rejected. `rootfs_source` and bind-mount host paths are resolved relative to the directory containing the YAML file.

Values explicitly supplied as CLI override options take precedence over the same values loaded from YAML.

### `--network-mode MODE`

Selects one of the following modes:

- `none` creates an isolated network namespace with initialized loopback, no host interface and no default route.
- `host` shares the host network namespace.
- `bridge` creates an isolated veth/bridge network and owned firewall policy.

### Bridge options

`--bridge-subnet`, `--bridge-gateway` and `--bridge-container-ip` configure bridge mode. The subnet must be canonical IPv4 CIDR, must leave usable host addresses, and must contain distinct gateway and payload addresses. These values do not take any effect without passing `--network-mode=bridge`.

Bridge mode requires effective `CAP_NET_ADMIN`, IPv4 forwarding, trusted `ip` and `iptables` executables and a subnet that does not conflict with host routes.

### `--env-whitelist NAME[,NAME...]`

Copies the named host variables when they exist. Names must be valid environment keys. Explicit YAML `env_vars` entries take precedence when the same key appears in both places. The remaining host environment variables are not inherited.

Example:

```bash
sandbox --env-whitelist=LANG,LC_ALL -- /bin/sh -c 'env'
```

### `--file-size-limit MIB`

Applies `RLIMIT_FSIZE` to each file created or extended by the payload. This is a per-file limit, not a total storage quota. Zero disables the configured limit, but a stricter limit may be inherited from the host.

### `--interactive` and `-i`

Allocates a pseudo-terminal, forwards terminal input and signals, tracks terminal resizing and restores the host terminal when the payload exits. Standard input must be a terminal.

Passing `--interactive` or `-i` enables the feature. It can also be written as `--interactive=true`, `--interactive=false`, `-i=true` or `-i=false`. Use ordinary non-interactive mode for pipelined I/O.

An explicit `TERM` in YAML `env_vars` is preserved. Otherwise, a short valid host `TERM` is copied; a missing or invalid value becomes `TERM=dumb`. `COLORTERM` is not copied automatically.

## Example policy

```yaml
command: ["/bin/sh", "-c", "cat /work/input/message.txt"]
working_dir: /work
network_mode: none
read_only_root: true

bind_mounts:
  - host_path: ./input
    container_path: /work/input

blocked_syscalls: ["mount", "reboot", "ptrace", "swapon", "syslog"]
blocked_syscall_action: kill
drop_capabilities: ["ALL"]
```

Host paths are resolved relative to the YAML file's directory. This makes a policy behave consistently regardless of the directory from which it is launched.

Unknown YAML fields, duplicate values and trailing YAML documents are rejected.

## Sharing files

Host paths are visible only when declared as bind mounts. They are read-only unless `writable: true` is explicitly set:

```yaml
bind_mounts:
  - host_path: ./input
    container_path: /work/input
  - host_path: ./output
    container_path: /work/output
    writable: true
```

Writes to a writable bind mount affect the host path. Other root filesystem writes, when enabled for a local root, use a private per-run overlay and do not modify the source rootfs.

## Networking

The supported modes are:

- `none` - private network namespace with loopback only; this is the default.
- `host` - share the host network namespace.
- `bridge` - create a veth/bridge network and owned firewall policy.

Examples:

```bash
sandbox --network-mode=none -- /bin/echo isolated
sandbox --network-mode=host -- /bin/echo host-network-enabled
```

Bridge mode is not rootless. It requires effective `CAP_NET_ADMIN`, trusted `ip` and `iptables` tools, IPv4 forwarding and a non-conflicting subnet.

## Environment and resource controls

The host environment variables are not inherited by default. Exact value in the policy file must be provided:

```yaml
env_vars:
  - PATH=/bin:/usr/bin
  - APP_MODE=production
env_whitelist: ["LANG"]
```

Optional limits:

```yaml
file_size_limit_mb: 100
cpu_limit_percent: 50
memory_limit_gb: 1
max_processes: 64
```

The file-size setting is a per-file `RLIMIT_FSIZE`, not a disk quota. CPU, memory, and process limits require writable delegated cgroup-v2 controllers. The sandbox fails if it cannot configure the requested limits.

## Root filesystem choices

### Managed root

Leave `rootfs_source` and `remote_rootfs` unset to use the default Alpine mini-root.

### Local root

```yaml
rootfs_source: ./rootfs
```

The directory must already contain the payload and its runtime dependencies.

### Remote root

```yaml
read_only_root: true
remote_rootfs:
  url: https://example.com/rootfs-amd64.tar.zst
  architecture: amd64
  archive_sha256: 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
  max_extracted_size_mb: 2048
```

Remote URLs must use HTTPS and the policy must include the SHA-256 digest. Downloads are verified before extraction and cached after successful validation.

## Complete YAML reference

The following policy contains every supported YAML option. `rootfs_source` and `remote_rootfs` are alternatives, so the local rootfs line is commented out. The values demonstrate syntax and are not a recommendation for options to use:

```yaml
command: ["/bin/sh", "-c", "exec /work/program --verbose"]
interactive: false

env_vars:
  - PATH=/bin:/usr/bin
  - APP_MODE=demo
env_whitelist: ["LANG", "TERM"]

working_dir: /work
read_only_root: true
# rootfs_source: ./rootfs
remote_rootfs:
  url: https://example.com/rootfs-amd64.tar.zst
  architecture: amd64
  archive_sha256: 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
  max_extracted_size_mb: 2048
  max_file_size_mb: 256
  max_entries: 200000

bind_mounts:
  - host_path: ./program
    container_path: /work/program
  - host_path: ./output
    container_path: /work/output
    writable: true

network_mode: none
bridge:
  subnet: 10.0.100.0/24
  gateway_ip: 10.0.100.1
  container_ip: 10.0.100.2
  mtu: 1500
dns_servers: ["1.1.1.1", "9.9.9.9"]

blocked_syscall_action: kill
blocked_syscalls: ["mount", "reboot", "ptrace", "swapon", "syslog"]
drop_capabilities: ["ALL"]

file_size_limit_mb: 100
cpu_limit_percent: 0
memory_limit_gb: 0
max_processes: 0
```

## Presentation code

The presentation examples verify the boundary from inside the payload and print `PASS` or `FAIL`:

```bash
sandbox --config examples/presentation/filesystem.yaml
sandbox --config examples/presentation/network-isolation.yaml
sandbox --config examples/presentation/identity-and-capabilities.yaml
sandbox --config examples/presentation/seccomp.yaml
```

These examples use a remote Ubuntu rootfs because their payloads require Python.

## Testing

Run the normal standalone checks:

```bash
cd sandbox/sandbox
go test -count=1 ./...
go vet ./...
go mod tidy -diff
```

For repository-wide Bazel validation:

```bash
bazel build //sandbox:sandbox
bazel test //sandbox:sandbox_tests
```

Some opt-in integration tests need network access, delegated cgroup-v2 controllers or `CAP_NET_ADMIN`. A restricted host may build the project while being unable to run those specific tests.

## Troubleshooting

**Namespace creation is denied**

Confirm that the Linux distribution and administrator policy allow unprivileged user namespaces.

**The payload is missing**

The selected rootfs must contain the executable and any dynamic libraries or other dependencies it needs.

**A host file is not visible**

Add it as a bind mount. Remember that `host_path` values are resolved relative to the YAML file.

**A cgroup limit cannot be applied**

Confirm that cgroup v2 is mounted and the requested controller is enabled and delegated to the current session.

**Bridge mode fails**

Check `CAP_NET_ADMIN`, IPv4 forwarding, the trusted `ip` and `iptables` executables, and subnet overlap.

**First-run rootfs provisioning fails**

Check HTTPS access and retry. Incomplete downloads are not published as valid cache entries.

## Project layout

- `sandbox/sandbox/` - current Go implementation
- `examples/` - user and presentation policies
- `docs/` - project reports, presentation content and demonstration script
- `sandbox/demo/` - frozen Python proof of concept
