#!/usr/bin/env bash
set -euo pipefail

server_dir="$(cd "$(dirname "$0")/.." && pwd)"
repo_root="$(cd "$server_dir/../.." && pwd)"

# Resolve before changing directory so a relative argument means what the
# caller sees.
mkdir -p "${1:-$server_dir/proving-keys}"
keys_dir="$(cd "${1:-$server_dir/proving-keys}" && pwd)"
vkey_dir="$repo_root/program-libs/interface/src/verifying_keys"
cd "$server_dir"

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
# RECEIPT_CAPACITIES.
for n_inputs in 8 512; do
    output="${keys_dir}/nullifier_receipt_${n_inputs}_0.key"
    echo "Generating nullifier-receipt ${n_inputs} -> ${output}"
    ./light-prover setup-receipt --n-inputs "$n_inputs" --output "$output" \
        --output-vkey "${output%.key}.vkbin"
    "$xtask" bsb22-vk "${output%.key}.vkbin" "$vkey_dir" "nullifier_receipt_${n_inputs}_0.rs"
done

rustfmt "$vkey_dir"/merge_receipt_*.rs "$vkey_dir"/nullifier_receipt_*.rs
echo "Done. Receipt proving keys written to ${keys_dir}; re-pin program-libs/interface/tests/vk_fingerprint.rs."
