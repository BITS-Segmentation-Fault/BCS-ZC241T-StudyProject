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
embedded SHA-256 digest, securely extracts it, writes a manifest, and publishes
it atomically. Later launches reuse the verified cache and work offline.

The cache is under `os.UserCacheDir()`:

```text
<user-cache>/bcs-zc241t-sandbox/rootfs/alpine/3.24.1/x86_64
<user-cache>/bcs-zc241t-sandbox/rootfs/alpine/3.24.1/aarch64
```

Go `amd64` maps to Alpine `x86_64`, and Go `arm64` maps to Alpine `aarch64`.
Other architectures are rejected before any network request. The archive name,
size ceiling, release URL, and digest are pinned in reviewed Go source; the
mutable `latest-stable` release path is not used.

To force a fresh managed download, remove the matching managed architecture
directory and launch again. A custom non-empty `rootfs_source` is user-managed:
it must already exist, is never downloaded or repaired, and is not modified by
the provisioning code. The payload must be present in the selected rootfs;
`/bin/echo` is available in the managed Alpine rootfs.

The namespace-free archive maintenance check can be run with
`SANDBOX_ALPINE_MAINTENANCE=1`; it downloads both pinned archives, verifies
their archive digests, extracts their production layouts, and verifies their
tree digests. The managed-rootfs E2E check can be enabled with
`SANDBOX_MANAGED_ROOTFS_E2E=1`; it uses a fresh temporary `XDG_CACHE_HOME`,
then repeats the launch with unusable proxy settings to verify offline reuse.

## Platform and runtime requirements

The program is Linux-only. Host and none modes are designed to work without
global root when unprivileged user namespaces, mount namespaces, PID/UTS
namespaces, `pivot_root`, `openat2`, the Linux new mount API
(`open_tree`, `mount_setattr`, `move_mount`, and
`fsopen`/`fsconfig`/`fsmount`), seccomp, and the required kernel policy are
available.
The configured rootfs must contain the command and its runtime
files; statically linked payloads are the simplest option. `/proc` is mounted
by the sandbox. The rootfs must already contain `/proc`, and must already
contain `/etc/resolv.conf` when DNS servers are configured. Every bind target
must also exist and match the source type; setup never creates target paths.

Bridge mode additionally requires root or `CAP_NET_ADMIN`, the `ip` command,
and `iptables`. It creates uniquely named links and owned NAT rules and rolls
back only resources created by that run. CPU limits from 1 through 100 require
a delegated CPU controller in a writable cgroup-v2 hierarchy; `0` disables
the CPU limit. If that controller is unavailable, configure
`cpu_limit_percent: 0` or provide the required delegation.
Aggregate memory and process limits are also disabled by default. Explicit
`memory_limit_gb` and `max_processes` values require delegated `memory` and
`pids` controllers in the same writable cgroup-v2 hierarchy.

The default security policy drops `ALL` capabilities and uses a killing
policy for blocked syscalls. Only `kill` and `trap` are accepted for that
policy. The denylist has an architecture guard but is not a complete syscall
allowlist or a guarantee against hostile workloads. Configuration names are
validated before a child or bridge is created. Use one `command` list in YAML or positional CLI arguments; public
flags must precede the command, and `--` explicitly terminates the flag
section. Environment names must be valid shell variable names and duplicate
keys are rejected.

Storage uses `RLIMIT_FSIZE`, which is a per-file size limit rather than a
total disk quota. Set `file_size_limit_mb` or `--file-size-limit`; zero
disables it. The limit is applied as both the soft and hard ceiling. Bind
mounts are read-only unless `writable: true` is explicitly configured.

## Frozen Python demo

The original Python proof-of-concept is frozen in `sandbox/demo`. Its Bazel
targets and usage instructions are documented separately in
[sandbox/demo/README.md](sandbox/demo/README.md). The frozen demo is not the
implementation or package entrypoint for the Go sandbox.
