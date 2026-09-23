#!/usr/bin/env bash
set -euo pipefail

# One-shot proving-key rotation. Run this whenever a circuit changes (the
# fingerprint test in prover/prover/fingerprint fails) or on a deliberate key
# refresh. It regenerates every proving key, regenerates the Rust verifying keys
# in both crates that embed them, refreshes the circuit fingerprints, regenerates
# the committed proving-keys.lock, and uploads the keys to a NEW immutable version
# folder in S3 (proving-keys/<version-hash>/). Because the folder is content-
# versioned, already-published CLIs keep fetching their own (unchanged) folder and
# nothing needs a CloudFront invalidation.
#
# The lockfile pins every key's sha256 and the version-hashed prefix; commit the
# regenerated proving-keys.lock together with the regenerated verifying keys in
# ONE PR so the on-chain vkeys and the pinned proving-key hashes can never drift.
# The CI cache key is derived from the lockfile hash, so it invalidates
# automatically -- no manual tag bump.
#
# Usage:
#   prover/server/scripts/rotate_proving_keys.sh [keys_dir]
#
# Requires the aws CLI with write access to the proving-keys bucket.
# Config: ZOLANA_PROVING_KEYS_BUCKET (default: zolana-proving-keys).

server_dir="$(cd "$(dirname "$0")/.." && pwd)"
repo_root="$(cd "$server_dir/../.." && pwd)"
keys_dir="${1:-$server_dir/proving-keys}"

bucket="${ZOLANA_PROVING_KEYS_BUCKET:-zolana-proving-keys}"

cd "$server_dir"
source scripts/ring_keys.sh
# keys_dir may be relative to prover/server; some steps below run from the repo
# root, so pin it to an absolute path first.
mkdir -p "$keys_dir"
keys_dir="$(cd "$keys_dir" && pwd)"
echo "==> building light-prover"
go build -o light-prover .

echo "==> generating transfer proving keys (all rails and shapes)"
bash scripts/generate_keys_transfer.sh "$keys_dir"

echo "==> generating merge proving keys"
bash scripts/generate_keys_merge.sh "$keys_dir"

echo "==> generating custom ring proving keys and their verifying keys"
bash scripts/generate_keys_custom_ring.sh "$keys_dir"

# The batched nullifier-tree (address-append) circuits build on circuits/gadget
# just like transfer/merge, so a gadget change rotates them too. Their vkeys are
# committed in the tree crate.
echo "==> generating batch address-append proving keys"
for spec in "10" "250"; do
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
bmt_vk_dir="$repo_root/program-libs/tree/src/nullifier_tree/verify/verifying_keys"
tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT
for spec in "10" "250"; do
    stem="batch_address-append_40_${spec}"
    module="batch_address_append_40_${spec}"
    ./light-prover export-vk --keys-file "$keys_dir/${stem}.key" --output "$tmp_dir/${stem}.vkbin" >/dev/null
    (cd "$repo_root" && cargo run -q -p xtask -- bsb22-vk \
        "$tmp_dir/${stem}.vkbin" \
        "$keys_dir/${stem}.key" \
        "program-libs/tree/src/nullifier_tree/verify/verifying_keys" \
        "${module}.rs")
done
echo "    wrote vkeys into $bmt_vk_dir"

echo "==> refreshing circuit fingerprints"
(cd "$repo_root" && UPDATE_FINGERPRINTS=1 go test -C prover/server ./prover/fingerprint/ -run TestCircuitFingerprints -v 2>&1 |
    grep -E '"[a-z].*constraints' || true)
echo "    paste the printed values into prover/server/prover/fingerprint/fingerprint_test.go"

echo "==> regenerating proving-keys.lock"
release_flags=()
sync_excludes=()
for key in "${ring_keys[@]}"; do
    release_flags+=(--release "$key")
    sync_excludes+=(--exclude "$key")
done
python3 scripts/generate_lockfile.py "$keys_dir" "${release_flags[@]}"

# The lock's prefix carries the new version hash; upload the full key set into that
# immutable version folder. Old version folders are left untouched, so previously
# published CLIs keep working -- no overwrite and no CloudFront invalidation.
lock_prefix="$(python3 -c "import json; print(json.load(open('prover/provingkeys/proving-keys.lock'))['prefix'])")"
echo "==> uploading proving keys to s3://$bucket/$lock_prefix/ (immutable version folder)"
aws s3 sync "$keys_dir/" "s3://$bucket/$lock_prefix/" --exclude '*' --include '*.key' "${sync_excludes[@]}"

cat <<EOF

==> rotation complete

Still MANUAL (one reviewed PR, so pk <-> vk <-> lock all move together):
  1. paste the refreshed fingerprints into
     prover/server/prover/fingerprint/fingerprint_test.go
  2. commit the regenerated verifying_keys/*.rs in the interface and
     tree crates
  3. commit the regenerated
     prover/server/prover/provingkeys/proving-keys.lock
     (its hash drives the CI cache key automatically -- no tag bump)
  4. update PROVING_KEY_SHA256S in sdk-libs/ts/src/interface/proving-keys.ts
     to the new lockfile digests (test/proving-keys.test.ts pins it)
  5. publish ${ring_keys[*]} with
     just release-custom-rings <tag> --upload --prerelease
EOF
