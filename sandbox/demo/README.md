# Frozen Python demo

This directory contains the original Python proof-of-concept. It is retained
for historical comparison and is not the active sandbox implementation.

Run it with Bazel:

```bash
bazel run //sandbox:demo -- -- echo "hello world"
bazel build //sandbox:demo_precompiled_zipapp
python3 bazel-bin/sandbox/demo/demo_precompiled_zipapp.pyz -- echo "hello world"
```

The Go sandbox lives in [`../sandbox`](../sandbox) and has its own standalone
Go build, test, and runtime workflow. The frozen demo should not be used for
new packaging or security work.
