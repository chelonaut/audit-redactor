#!/usr/bin/env bash
# Convenience wrapper around the audit-redactor Docker image. Unlike
# `make run` (which always bind-mounts the repo root at /data), this works
# against *any* host path -- input/output can live anywhere on disk, e.g.
# ~/Downloads/some-folder -- by figuring out which host directories
# actually need to be mounted and mounting exactly those.
#
# Usage: ./redact.sh <input> <output> [--offline]
#   <input>/<output> may be absolute or relative paths to a file or a
#   directory (batch mode). Glob patterns (e.g. "docs/**/*.pdf") are not
#   supported by this wrapper -- use `make run ARGS="redact '...'"` directly
#   for those, since resolving a glob's mount point on the host isn't as
#   simple as "the containing directory."
#
#   If ANTHROPIC_API_KEY is set in your shell, it's forwarded into the
#   container automatically, enabling the Claude augmentation pass. Unset
#   (or pass --offline) to run local-only.
#
#   Your curated, private company-name list (see cli.py's --company-list)
#   is picked up the same way: set AUDIT_REDACTOR_COMPANY_LIST once in your
#   shell profile (defaults to ~/client_names.txt if unset) and this script
#   bind-mounts that exact file into the container and forwards the
#   variable -- no --company-list flag needed here. A CLI flag would need
#   this script to inspect "$@" just to find the path to mount, which is
#   exactly the parsing an env var avoids; if the file doesn't exist, it's
#   silently skipped and the containerized CLI falls back to its own
#   bundled-sample-list warning.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

if [[ $# -lt 2 ]]; then
    echo "Usage: $0 <input> <output> [--offline]" >&2
    exit 1
fi

input="$1"
output="$2"
shift 2

image="audit-redactor:dev"
docker build -t "$image" . >&2

# Print the absolute path of the directory that should be bind-mounted for
# a given input/output argument: the path itself if it's already a
# directory, otherwise its parent (which must exist for `-v` to work, so
# it's created first -- relevant for OUTPUT, which usually doesn't exist
# yet on a fresh run).
_mount_dir() {
    local path="$1"
    if [[ -d "$path" ]]; then
        (cd "$path" && pwd)
    else
        mkdir -p "$(dirname -- "$path")"
        (cd "$(dirname -- "$path")" && pwd)
    fi
}

# Print the container-side path corresponding to a host path once its
# mount root (from _mount_dir) is mounted at $2 -- empty if the path is a
# bare directory (the mount root itself), else "$2/<basename>".
_container_path() {
    local path="$1" mount_point="$2"
    if [[ -d "$path" ]]; then
        printf '%s' "$mount_point"
    else
        printf '%s/%s' "$mount_point" "$(basename -- "$path")"
    fi
}

input_host_dir="$(_mount_dir "$input")"
output_host_dir="$(_mount_dir "$output")"
input_container="$(_container_path "$input" /input)"
output_container="$(_container_path "$output" /output)"

# Only bind-mount + forward the company list if the file actually exists --
# `docker run -v` on a missing host path creates an empty directory there
# instead of erroring, which would both fail to help and leave stray litter
# at (most likely) the user's chosen path.
company_list_host="${AUDIT_REDACTOR_COMPANY_LIST:-$HOME/client_names.txt}"
company_list_args=()
if [[ -f "$company_list_host" ]]; then
    company_list_args=(-v "$company_list_host:/company_names.txt:ro" -e AUDIT_REDACTOR_COMPANY_LIST=/company_names.txt)
fi

docker run --rm \
    -e ANTHROPIC_API_KEY \
    "${company_list_args[@]+"${company_list_args[@]}"}" \
    -v "$input_host_dir:/input:ro" \
    -v "$output_host_dir:/output" \
    "$image" redact "$input_container" "$output_container" "$@"
