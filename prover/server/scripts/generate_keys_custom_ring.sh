#!/usr/bin/env bash
set -euo pipefail

# gnark's Setup is non-deterministic, one run writes the proving key, the
# committed Rust verifying key and the proving-keys.lock entry together.

server_dir="$(cd "$(dirname "$0")/.." && pwd)"
repo_root="$(cd "$server_dir/../.." && pwd)"
keys_dir="${1:-$server_dir/proving-keys}"
mkdir -p "$keys_dir"
keys_dir="$(cd "$keys_dir" && pwd)"
cd "$server_dir"
vkey_dir="$repo_root/custom-rings/interface/src"
tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

go build -o light-prover .
(cd "$repo_root" && cargo build -q -p xtask)
xtask="$repo_root/target/debug/xtask"

echo "Generating custom-ring -> ${keys_dir}/custom_ring.key"
./light-prover setup-custom-ring --output "$keys_dir/custom_ring.key" --vk-out "$tmp_dir/custom_ring.vkbin"
echo "Generating audit -> ${keys_dir}/audit.key"
./light-prover setup-audit --output "$keys_dir/audit.key" --vk-out "$tmp_dir/audit.vkbin"

for pair in custom_ring:verifying_key.rs audit:audit_verifying_key.rs; do
    stem="${pair%%:*}"
    module="${pair##*:}"
    "$xtask" bsb22-vk "$tmp_dir/$stem.vkbin" "$vkey_dir" "$module"
    rustfmt "$vkey_dir/$module"
done

python3 scripts/generate_lockfile.py "$keys_dir" --release custom_ring.key --release audit.key --only-release

echo "Done. Ring proving keys in ${keys_dir}, verifying keys in ${vkey_dir}"
