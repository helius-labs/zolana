#!/usr/bin/env bash
set -euo pipefail

# Package E rotation, local half only: regenerate every proving key whose circuit
# moved, regenerate the verifying keys both Rust crates embed, and regenerate the
# lockfile. It does NOT upload to S3. The upload stays with the key owner.

server_dir="$(cd "$(dirname "$0")/.." && pwd)"
repo_root="$(cd "$server_dir/../.." && pwd)"
keys_dir="${1:-$server_dir/proving-keys}"
mkdir -p "$keys_dir"
keys_dir="$(cd "$keys_dir" && pwd)"

cd "$server_dir"
echo "==> building light-prover"
go build -o light-prover .

echo "==> generating transfer proving keys (all rails and shapes)"
bash scripts/generate_keys_transfer.sh "$keys_dir"

echo "==> generating merge proving keys"
bash scripts/generate_keys_merge.sh "$keys_dir"

tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

echo "==> generating batch address-append proving keys"
for spec in "10" "4999"; do
    ./light-prover setup \
        --circuit address-append \
        --address-append-tree-height 40 \
        --address-append-batch-size "$spec" \
        --output "$keys_dir/batch_address-append_40_${spec}.key" \
        --output-vkey "$keys_dir/batch_address-append_40_${spec}.vkey"
done

echo "==> regenerating interface verifying keys"
bash scripts/regenerate_all_vkeys.sh "$keys_dir"

echo "==> regenerating nullifier-tree verifying keys (address-append)"
for spec in "10" "4999"; do
    stem="batch_address-append_40_${spec}"
    module="batch_address_append_40_${spec}"
    ./light-prover export-vk --keys-file "$keys_dir/${stem}.key" --output "$tmp_dir/${stem}.vkbin" >/dev/null
    (cd "$repo_root" && cargo run -q -p xtask -- bsb22-vk \
        "$tmp_dir/${stem}.vkbin" \
        "$keys_dir/${stem}.key" \
        "program-libs/tree/src/nullifier_tree/verify/verifying_keys" \
        "${module}.rs")
done

echo "==> regenerating proving-keys.lock"
python3 scripts/generate_lockfile.py "$keys_dir" --prover ./light-prover

echo "==> local rotation complete; S3 upload is the owner's step"
