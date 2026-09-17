#!/usr/bin/env bash
set -euo pipefail

server_dir="$(cd "$(dirname "$0")/.." && pwd)"
repo_root="$(cd "$server_dir/../.." && pwd)"
cd "$server_dir"

keys_dir="${1:-./proving-keys}"
vkey_dir="$repo_root/program-libs/interface/src/verifying_keys"
mkdir -p "$keys_dir"

# Rebuild right before setup: a stale binary compiles a different constraint
# system than the running server.
go build -o light-prover .
(cd "$repo_root" && cargo build -q -p xtask)
xtask="$repo_root/target/debug/xtask"

# Receipt-backed merge: same shapes as the default merge (merge_receipt_<n>_1).
for n_inputs in 8 36; do
    output="${keys_dir}/merge_receipt_${n_inputs}_1.key"
    echo "Generating merge-receipt ${n_inputs}x1 -> ${output}"
    ./light-prover setup-merge --circuit merge-receipt --n-inputs "$n_inputs" --output "$output"
    ./light-prover export-vk --keys-file "$output" --output "${output%.key}.vkbin" >/dev/null
    "$xtask" bsb22-vk "${output%.key}.vkbin" "$vkey_dir" "merge_receipt_${n_inputs}_1.rs"
done

# Nullifier receipt: keep in sync with receipt.SupportedNInputs and
# RECEIPT_CAPACITIES. 512 needs roughly 16 GB during setup.
for n_inputs in 8 512; do
    output="${keys_dir}/nullifier_receipt_${n_inputs}_0.key"
    echo "Generating nullifier-receipt ${n_inputs} -> ${output}"
    ./light-prover setup-receipt --n-inputs "$n_inputs" --output "$output" \
        --output-vkey "${output%.key}.vkbin"
    "$xtask" bsb22-vk "${output%.key}.vkbin" "$vkey_dir" "nullifier_receipt_${n_inputs}_0.rs"
done

rustfmt "$vkey_dir"/merge_receipt_*.rs "$vkey_dir"/nullifier_receipt_*.rs
echo "Done. Receipt proving keys written to ${keys_dir}; register new modules in ${vkey_dir}/mod.rs"
echo "and re-pin program-libs/interface/tests/vk_fingerprint.rs."
