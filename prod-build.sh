#!/usr/bin/env bash

set -euo pipefail

bazel build --build_python_zip=true "$@"
