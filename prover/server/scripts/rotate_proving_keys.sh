#!/usr/bin/env bash
set -euo pipefail

# One-shot proving-key rotation. Run this whenever a circuit changes (the
# fingerprint test in prover/prover/fingerprint fails) or on a deliberate key
# refresh. It regenerates every proving key, regenerates and commits the Rust
# verifying keys in both crates that embed them, refreshes the circuit
# fingerprints, and publishes the GitHub release. Bumping the pinned tag and CI
# cache key is a separate reviewed edit (see the printed reminder) so the tag
# change lands in the same PR as the keys it points at.
#
# Usage:
#   prover/server/scripts/rotate_proving_keys.sh <tag> [keys_dir]
#
# <tag> MUST equal common.ProvingKeysReleaseTag after you bump it. Requires
# GH_TOKEN / GITHUB_TOKEN with write access to the release repo.

if [[ $# -lt 1 ]]; then
    echo "usage: $0 <tag> [keys_dir]" >&2
    exit 1
fi

tag="$1"
server_dir="$(cd "$(dirname "$0")/.." && pwd)"
repo_root="$(cd "$server_dir/../.." && pwd)"
keys_dir="${2:-$server_dir/proving-keys}"

cd "$server_dir"
echo "==> building light-prover"
go build -o light-prover .

echo "==> generating transfer proving keys (all rails and shapes)"
bash scripts/generate_keys_transfer.sh "$keys_dir"

echo "==> generating merge proving keys"
bash scripts/generate_keys_merge.sh "$keys_dir"

# The batched nullifier-tree (address-append) circuits build on circuits/gadget
# just like transfer/merge, so a gadget change rotates them too. Their vkeys are
# committed in the batched-merkle-tree crate.
echo "==> generating batch address-append proving keys"
for spec in "10" "250"; do
    ./light-prover setup \
        --circuit address-append \
        --address-append-tree-height 40 \
        --address-append-batch-size "$spec" \
        --output "$keys_dir/batch_address-append_40_${spec}.key" \
        --output-vkey "$keys_dir/batch_address-append_40_${spec}.vkey"
done

echo "==> regenerating interface verifying keys (transfer + merge)"
bash scripts/regenerate_all_vkeys.sh "$keys_dir"

echo "==> regenerating batched-merkle-tree verifying keys (address-append)"
bmt_vk_dir="$repo_root/program-libs/batched-merkle-tree/src/verify/verifying_keys"
tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT
for spec in "10" "250"; do
    stem="batch_address-append_40_${spec}"
    module="batch_address_append_40_${spec}"
    ./light-prover export-vk --keys-file "$keys_dir/${stem}.key" --output "$tmp_dir/${stem}.vkbin" >/dev/null
    key_sha256="$(shasum -a 256 "$keys_dir/${stem}.key" | awk '{print $1}')"
    (cd "$repo_root" && cargo run -q -p xtask -- bsb22-vk \
        "$tmp_dir/${stem}.vkbin" \
        "program-libs/batched-merkle-tree/src/verify/verifying_keys" \
        "${module}.rs" "$key_sha256")
done
echo "    wrote vkeys into $bmt_vk_dir"

echo "==> refreshing circuit fingerprints"
(cd "$repo_root" && UPDATE_FINGERPRINTS=1 go test -C prover/server ./prover/fingerprint/ -run TestCircuitFingerprints -v 2>&1 |
    grep -E '"[a-z].*constraints' || true)
echo "    paste the printed values into prover/server/prover/fingerprint/fingerprint_test.go"

echo "==> publishing release $tag"
bash scripts/publish_keys_release.sh "$tag" "$keys_dir"

cat <<EOF

==> rotation complete for $tag

Still MANUAL (single reviewed diff, same PR as the committed vkeys):
  1. set common.ProvingKeysReleaseTag = "$tag" in
     prover/server/prover/common/key_downloader.go
  2. bump the proving-keys-<tag> cache key in .github/workflows/{rust,async-prover}.yml
  3. paste the refreshed fingerprints into prover/prover/fingerprint/fingerprint_test.go
  4. update the release tag references in CLAUDE.md and justfile
  5. commit the regenerated verifying_keys/*.rs in both crates
EOF
