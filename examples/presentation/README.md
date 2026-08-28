# Presentation demonstrations

Each YAML file is a self-contained presentation scenario. The examples use a
pinned Ubuntu 24.04 archive because the demonstration payloads require Python.

Run them from the repository root (or any other directory):

```bash
sandbox --config examples/presentation/filesystem.yaml
sandbox --config examples/presentation/network-isolation.yaml
sandbox --config examples/presentation/identity-and-capabilities.yaml
sandbox --config examples/presentation/seccomp.yaml
```

The demonstrations print `PASS` or `FAIL` for the behavior they inspect. The
sandbox require a Linux host capable of user and mount namespaces.
