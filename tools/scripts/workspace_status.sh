#!/usr/bin/env bash
set -euo pipefail

readonly root="${BUILD_WORKSPACE_DIRECTORY:-.}"
readonly ts="$(git -C "$root" log -1 --format=%ct 2>/dev/null || echo 0)"
echo "STABLE_GIT_TIMESTAMP ${ts}"
