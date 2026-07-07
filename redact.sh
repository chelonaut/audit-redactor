#!/usr/bin/env bash
# Convenience wrapper around `make run` so you don't have to remember the
# ARGS= / docker-run incantation or the container's /data mount point.
#
# Usage: ./redact.sh <input> <output> [--offline]
#   Paths must be relative to (or inside) the repo root, since that's what
#   the Makefile's `run` target bind-mounts to /data in the container. Each
#   non-flag argument is auto-prefixed with /data/ so you can just pass plain
#   relative paths, e.g.: ./redact.sh docs/report.pdf out/report.pdf
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

args=()
for arg in "$@"; do
    if [[ "$arg" == -* ]]; then
        args+=("$arg")
    else
        args+=("/data/$arg")
    fi
done

make run ARGS="redact ${args[*]}"
