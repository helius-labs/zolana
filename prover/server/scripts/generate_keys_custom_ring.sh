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

echo "Generating custom-ring-policy -> ${keys_dir}/custom_ring_policy.key"
./light-prover setup-custom-ring-policy --output "$keys_dir/custom_ring_policy.key" --vk-out "$tmp_dir/custom_ring_policy.vkbin"
echo "Generating custom-ring-base -> ${keys_dir}/custom_ring_base.key"
./light-prover setup-custom-ring-base --output "$keys_dir/custom_ring_base.key" --vk-out "$tmp_dir/custom_ring_base.vkbin"

for pair in custom_ring_policy:policy_verifying_key.rs custom_ring_base:base_verifying_key.rs; do
    stem="${pair%%:*}"
    module="${pair##*:}"
    "$xtask" bsb22-vk "$tmp_dir/$stem.vkbin" "$vkey_dir" "$module"
    rustfmt "$vkey_dir/$module"
done

python3 scripts/generate_lockfile.py "$keys_dir" --release custom_ring_policy.key --release custom_ring_base.key --only-release

echo "Done. Ring proving keys in ${keys_dir}, verifying keys in ${vkey_dir}"
