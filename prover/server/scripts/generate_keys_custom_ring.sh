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
source scripts/ring_keys.sh
vkey_dir="$repo_root/custom-rings/interface/src"
tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

go build -o light-prover .
(cd "$repo_root" && cargo build -q -p xtask)
xtask="$repo_root/target/debug/xtask"

release_flags=()
for key in "${ring_keys[@]}"; do
    stem="${key%.key}"
    circuit="${stem//_/-}"
    module="${stem#custom_ring_}_verifying_key.rs"
    echo "Generating ${circuit} -> ${keys_dir}/${key}"
    ./light-prover "setup-${circuit}" --output "$keys_dir/$key" --vk-out "$tmp_dir/$stem.vkbin"
    "$xtask" bsb22-vk "$tmp_dir/$stem.vkbin" "$vkey_dir" "$module"
    rustfmt "$vkey_dir/$module"
    release_flags+=(--release "$key")
done

python3 scripts/generate_lockfile.py "$keys_dir" "${release_flags[@]}" --only-release

echo "Done. Ring proving keys in ${keys_dir}, verifying keys in ${vkey_dir}"
