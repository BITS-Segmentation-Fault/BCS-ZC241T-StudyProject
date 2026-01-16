#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 5 ]]; then
    echo "USAGE: $0 TYPST_PATH VERSION_FILE PDF_STANDARD MAIN OUT" >&2
    exit 1
fi

readonly typst="$1"
readonly version_file="$2"
readonly pdf_standard="$3"
readonly main="$4"
readonly out="$5"

readonly ts="$(awk '$1=="STABLE_GIT_TIMESTAMP"{print $2; exit}' "$version_file" || true)"
if [[ -z "${ts:-}" ]]; then
    echo "ERROR: STABLE_GIT_TIMESTAMP missing" >&2
    exit 1
fi

exec "$typst" compile \
    --format pdf \
    --ignore-system-fonts \
    --creation-timestamp "$ts" \
    --pdf-standard "$pdf_standard" \
    "$main" \
    "$out"
