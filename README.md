# BCS ZC241T StudyProject

## Go sandbox

The active sandbox is the standalone Go module in `sandbox/sandbox`. Bazel is
an integration and packaging layer; ordinary Go tooling is the authoritative
build and test workflow.

From the module directory:

```bash
cd sandbox/sandbox
go build ./...
go test ./...
go vet ./...
go run . --network-mode=none -- /bin/echo "hello world"
```

Use a temporary output path when a standalone executable is needed:

```bash
go build -o "${TMPDIR:-/tmp}/sandbox" .
```

With a freshly built binary, the equivalent first-run command is:

```bash
./sandbox-bin --network-mode=none -- /bin/echo "hello world"
```

Bazel mirrors the module and packages the executable without writing build
outputs into the source tree:

```bash
bazel build //sandbox:sandbox
bazel test //sandbox:sandbox_tests
bazel build //pkg:study_project_dist
```

The distribution archive contains the executable at `sandbox/sandbox` with
its executable permission preserved.

## Managed rootfs

If `rootfs_source` is omitted or empty, the host-side parent provisions the
managed rootfs before creating cgroups, network resources, or namespaces. This
also applies when the requested network mode is `none`. The first launch
downloads the pinned Alpine 3.24.1 minirootfs archive over HTTPS, verifies its
pinned SHA-256 digest, securely extracts it, writes a manifest, and publishes
it atomically. Later launches reuse the verified cache and work offline.

The cache is under `os.UserCacheDir()`:

```text
<user-cache>/bcs-zc241t-sandbox/rootfs/alpine/3.24.1/x86_64
<user-cache>/bcs-zc241t-sandbox/rootfs/alpine/3.24.1/aarch64
```

Go `amd64` maps to Alpine `x86_64`, and Go `arm64` maps to Alpine `aarch64`.
Other architectures are rejected before any network request. The archive name,
release URL, and digests are pinned in reviewed Go source; the mutable
`latest-stable` release path is not used. Downloads stream to temporary storage
without a fixed compressed-size ceiling; extracted and cached trees are limited
to 512 MiB total, 128 MiB per file, and 100,000 entries.

To force a fresh managed download, remove the matching managed architecture
directory and launch again. A custom non-empty `rootfs_source` is user-managed
and may contain any compatible Linux rootfs: it must already exist, is never
downloaded or repaired, and is not modified by the provisioning code. The
payload must be present in the selected rootfs;
`/bin/echo` is available in the managed Alpine rootfs.

For a verified remote rootfs, configure `remote_rootfs` instead of
`rootfs_source`:

```yaml
remote_rootfs:
  url: https://example.com/rootfs-amd64.tar.gz
  architecture: amd64
  archive_sha256: 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
  # tree_sha256: optional pinned digest of the extracted tree
```

The remote URL must be HTTPS and the archive SHA-256 is mandatory; it must be
lowercase and exactly 64 hexadecimal characters. Remote archives are cached
under their digest, never under their URL, and are extracted only after the
downloaded bytes match that digest. The extracted tree is then hashed and
verified on every reuse. Archive format is identified from content, so any
unencrypted archive recognized by the pinned archive library may be used when
its entries form a valid rootfs tree. Compressed files that are not archives
and unsafe entry types are rejected, and archive metadata is not restored. Remote
rootfs launches must keep
`read_only_root: true`; local and remote rootfs sources cannot be combined. A failed remote
download never falls back to the built-in Alpine rootfs.

When a configuration is loaded from a YAML file, a non-empty relative
`rootfs_source` and each non-empty relative `bind_mounts[].host_path` are
resolved relative to that file's directory. Empty host paths remain invalid.
`working_dir` and bind `container_path` values are sandbox paths and are not
resolved against the YAML file. Reader-based configuration loading has no
filename context, so it continues to require absolute host paths.

The namespace-free archive maintenance check can be run with
`SANDBOX_ALPINE_MAINTENANCE=1`; it downloads both pinned archives, verifies
their archive digests, securely extracts them, and verifies their tree digests.
The managed-rootfs E2E check can be enabled with
`SANDBOX_MANAGED_ROOTFS_E2E=1`; it uses a fresh temporary `XDG_CACHE_HOME`,
then repeats the launch with unusable proxy settings to verify offline reuse.

## Platform and runtime requirements

The program is Linux-only and executable targets are currently limited to
amd64 and arm64. Host and none modes are designed to work without
global root when unprivileged user namespaces, mount namespaces, PID/UTS
namespaces, `pivot_root`, `openat2`, the Linux new mount API
(`open_tree`, `mount_setattr`, `move_mount`, and
`fsopen`/`fsconfig`/`fsmount`), seccomp, and the required kernel policy are
available.
The configured rootfs must contain the command and its runtime files; statically
linked payloads are the simplest option. `/proc` is mounted by the sandbox. If
the root must be writable, or a required mount target is missing, the sandbox
assembles a private overlay and creates missing targets there. The configured
rootfs is never changed. Existing targets must match their source type, and
symlinked paths or unsafe target paths are rejected.
`read_only_root: false` is a per-run writable overlay: changes disappear when
the sandbox exits and are never written back to the rootfs source.

Bridge mode additionally requires effective `CAP_NET_ADMIN`, trusted `ip` and
`iptables` commands, and enabled IPv4 forwarding. It creates uniquely named
links and owned firewall rules and rolls
back only resources created by that run. CPU limits from 1 through 100 require
a delegated CPU controller in a writable cgroup-v2 hierarchy; `0` disables
the CPU limit. If that controller is unavailable, configure
`cpu_limit_percent: 0` or provide the required delegation.
Aggregate memory and process limits are also disabled by default. Explicit
`memory_limit_gb` and `max_processes` values require delegated `memory` and
`pids` controllers in the same writable cgroup-v2 hierarchy. A CPU percentage
is a quota relative to one CPU over the selected period. `max_processes` maps
to `pids.max`, which counts sandbox infrastructure and kernel tasks, including
Go runtime threads. Memory limiting also disables additional swap. All limits
require the relevant controllers to be enabled in a writable delegated
cgroup-v2 hierarchy.

The default security policy drops `ALL` capabilities and uses a killing
policy for blocked syscalls. Only `kill` and `trap` are accepted: `kill`
terminates the process and `trap` delivers `SIGSYS`. The accepted blocked
syscall names are `reboot`, `mount`, `ptrace`, `swapon`, `syslog`,
`init_module`, `finit_module`, `delete_module`, `kcmp`, `process_vm_readv`,
and `process_vm_writev`; `iopl` and `ioperm` are amd64-only. The denylist has
an architecture guard but is not a complete syscall allowlist or a guarantee
against hostile workloads. Configuration names are validated before a child
or bridge is created. Use one `command` list in YAML or positional CLI arguments; public
flags must precede the command, and `--` explicitly terminates the flag
section. Environment names must be valid shell variable names and duplicate
keys are rejected.

Standard output belongs to the payload. Sandbox diagnostics, including setup
failures, are written to standard error.

Storage uses `RLIMIT_FSIZE`, which is a per-file size limit rather than a
total disk quota. Set `file_size_limit_mb` or `--file-size-limit`; zero
disables it. The limit is applied as both the soft and hard ceiling. Bind
mounts are read-only unless `writable: true` is explicitly configured.

## Frozen Python demo

The original Python proof-of-concept is frozen in `sandbox/demo`. Its Bazel
targets and usage instructions are documented separately in
[sandbox/demo/README.md](sandbox/demo/README.md). The frozen demo is not the
implementation or package entrypoint for the Go sandbox.
