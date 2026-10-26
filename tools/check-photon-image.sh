#!/usr/bin/env bash
set -euo pipefail
if [[ $# != 1 ]]; then
    echo "Usage: $0 IMAGE" >&2
    exit 1
fi
for binary in photon photon-migration photon-snapshotter photon-snapshot-loader; do
    docker run --rm --entrypoint "$binary" "$1" --version
done
test "$(docker run --rm --entrypoint id "$1" -u)" = 10001
