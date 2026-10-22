#!/usr/bin/env bash
set -euo pipefail

# gnark's Setup is non-deterministic, one run writes the proving key, the
# committed Rust verifying key and the proving-keys.lock entry together.

server_dir="$(cd "$(dirname "$0")/.." && pwd)"
repo_root="$(cd "$server_dir/../.." && pwd)"
keys_dir="${1:-$server_dir/proving-keys}"
mkdir -p "$keys_dir" "$repo_root/target"
keys_dir="$(cd "$keys_dir" && pwd)"
cd "$server_dir"
go build -o "$repo_root/target/prover-server" .
(cd "$repo_root" && cargo build -q -p xtask)
python3 scripts/generate_ring_keys.py --keys-dir "$keys_dir" "${@:2}"
