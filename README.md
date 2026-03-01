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

Use the `prod-build.sh` helper script:

```bash
./prod-build.sh //sandbox:demo_precompiled
```

Run the built Python zipapp binary:

```bash
python ./bazel-bin/sandbox/demo/demo_precompiled.zip <options>
```

### Examples

1. Hello, world!
   ```bash
   python ./bazel-bin/sandbox/demo/demo_precompiled.zip -- echo "hello world"
   ```
2. `id` command
   ```bash
   python ./bazel-bin/sandbox/demo/demo_precompiled.zip -- id
   ```
3. internet on (default)
   ```bash
   python ./bazel-bin/sandbox/demo/demo_precompiled.zip -- nslookup google.com
   ```
4. internet off (network mode = "none")
   ```bash
   python ./bazel-bin/sandbox/demo/demo_precompiled.zip --network-mode=none -- nslookup google.com
   ```
5. verbose logging (`true` is a linux command that exits with code 0)
   ```bash
   python ./bazel-bin/sandbox/demo/demo_precompiled.zip --verbose -- true
   ```
