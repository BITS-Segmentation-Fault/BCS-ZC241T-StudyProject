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
go run . -- --network-mode=none -- /bin/echo "hello world"
```

Use a temporary output path when a standalone executable is needed:

```bash
go build -o "${TMPDIR:-/tmp}/sandbox" .
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

## Platform and runtime requirements

The program is Linux-only. Host and none modes are designed to work without
global root when unprivileged user namespaces, mount namespaces, PID/UTS
namespaces, `pivot_root`, `openat2`, seccomp, and the required kernel policy
are available. The configured rootfs must contain the command and its runtime
files; statically linked payloads are the simplest option. `/proc` is mounted
by the sandbox.

Bridge mode additionally requires root or `CAP_NET_ADMIN`, the `ip` command,
and `iptables`. It creates uniquely named links and owned NAT rules and rolls
back only resources created by that run. CPU limits from 1 through 100 require
a delegated CPU controller in a writable cgroup-v2 hierarchy; `0` disables
the CPU limit. If that controller is unavailable, configure
`cpu_limit_percent: 0` or provide the required delegation.

The default security policy drops `ALL` capabilities and uses a killing
seccomp policy. Configuration names are validated before a child or bridge is
created. Use `--config PATH` for YAML settings; public flags must precede the
command, and `--` explicitly terminates the flag section.

Storage uses `RLIMIT_FSIZE`, which is a per-file size limit rather than a
total disk quota. The initial limit is applied as both the soft and hard
ceiling. The historical maximum and expansion fields remain parse-compatible,
but expansion policies are rejected.

## Frozen Python demo

The original Python proof-of-concept is frozen in `sandbox/demo`. Its Bazel
targets and usage instructions are documented separately in
[sandbox/demo/README.md](sandbox/demo/README.md). The frozen demo is not the
implementation or package entrypoint for the Go sandbox.
