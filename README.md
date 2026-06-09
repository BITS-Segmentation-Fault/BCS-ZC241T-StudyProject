# BCS ZC241T StudyProject

## How to run and/or build the demo

### CLI help/usage

```
usage: main.py [-h] [--network-mode NETWORK_MODE] [--verbose] command [command ...]

positional arguments:
  command               Command to execute inside the sandbox.

options:
  -h, --help            show this help message and exit
  --network-mode NETWORK_MODE
                        Set to "none" to disable internet access. Default: "host" (no network restrictions).
  --verbose
```

### Developer run workflow

```bash
bazel run //sandbox:demo -- <options>
```

### Production build workflow

```bash
bazel build //sandbox:demo_precompiled_zipapp
```

Run the built Python zipapp binary:

```bash
python3 ./bazel-bin/sandbox/demo/demo_precompiled_zipapp.pyz <options>
```

### Examples

1. Hello, world!
   ```bash
   python3 ./bazel-bin/sandbox/demo/demo_precompiled_zipapp.pyz -- echo "hello world"
   ```
2. `id` command
   ```bash
   python3 ./bazel-bin/sandbox/demo/demo_precompiled_zipapp.pyz -- id
   ```
3. internet on (default)
   ```bash
   python3 ./bazel-bin/sandbox/demo/demo_precompiled_zipapp.pyz -- nslookup google.com
   ```
4. internet off (network mode = "none")
   ```bash
   python3 ./bazel-bin/sandbox/demo/demo_precompiled_zipapp.pyz --network-mode=none -- nslookup google.com
   ```
5. verbose logging (`true` is a linux command that exits with code 0)
   ```bash
   python3 ./bazel-bin/sandbox/demo/demo_precompiled_zipapp.pyz --verbose -- true
   ```
