#!/usr/bin/env bash
set -euo pipefail
if [[ $# != 1 || $1 == --help ]]; then
    echo "Usage: $0 OUTPUT_DIRECTORY"
    exit 0
fi
root=$(cd "$(dirname "$0")/../.." && pwd)
lock="$root/prover/server/prover/backend/aeglos-source.lock"
read -r digest archive < "$lock"
[[ $digest =~ ^[0-9a-f]{64}$ && $archive =~ ^aeglos-([0-9a-f]{40})\.tar$ ]]
revision=${BASH_REMATCH[1]}
mkdir -p "$1"
output=$(cd "$1" && pwd)
scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT
if [[ ! -f $output/$archive ]]; then
    git init -q "$scratch"
    GIT_TERMINAL_PROMPT=0 git -C "$scratch" fetch -q --depth=1 https://github.com/helius-labs/aeglos.git "$revision"
    git -C "$scratch" archive --format=tar --output="$scratch/$archive" FETCH_HEAD
    (cd "$scratch" && shasum -a 256 -c "$lock")
    mv "$scratch/$archive" "$output/$archive"
fi
(cd "$output" && shasum -a 256 -c "$lock")
