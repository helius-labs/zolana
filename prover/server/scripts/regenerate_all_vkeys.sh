#!/usr/bin/env bash
set -euo pipefail

server_dir="$(cd "$(dirname "$0")/.." && pwd)"
repo_root="$(cd "$server_dir/../.." && pwd)"
cd "$server_dir"

keys_dir="${1:-./proving-keys}"
vkey_dir="$repo_root/program-libs/interface/src/verifying_keys"
tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

go build -o light-prover .
(cd "$repo_root" && cargo build -q -p xtask)
xtask="$repo_root/target/debug/xtask"

# `merge-chain_*` is matched separately because it is not `merge_*`. A glob
# that misses a key regenerates no constant for it, which leaves that constant
# pinned to a key nobody holds.
keys="$(find "$keys_dir" -maxdepth 1 -type f \
    \( -name 'transfer_*.key' -o -name 'merge_*.key' -o -name 'merge-chain_*.key' -o -name 'aggregate_*.key' \) |
    sort)"
if [ -z "$keys" ]; then
    echo "no transfer, merge, or aggregate proving keys in $keys_dir"
    exit 1
fi

# The module list is what git tracks, not what this machine happens to hold.
# Deriving it from local keys would drop the declaration for every committed
# constant whose key is absent here and break the build for everyone else.
modules="$(git -C "$vkey_dir" ls-files '*.rs' |
    sed 's/\.rs$//' |
    grep -vxE 'mod|aggregate|circuit|merge_chain|catalog|registry|registry_spec')"
for key in $keys; do
    stem="$(basename "$key" .key)"
    module="${stem//-/_}"
    vk_bin="$tmp_dir/${stem}.vkbin"

    # Only regenerate verifying keys that already exist in git. Deprecated key
    # shapes (the plain transfer_* / transfer_p256_* combinations) remain on
    # disk but have no committed vk. Skip them rather than mint spurious files.
    if ! git ls-files --error-unmatch "$vkey_dir/${module}.rs" >/dev/null 2>&1; then
        continue
    fi

    echo "exporting raw vk: $stem"
    if ! ./light-prover export-vk --keys-file "$key" --output "$vk_bin" >/dev/null; then
        echo "export-vk failed for $stem" >&2
        exit 1
    fi

    if ! "$xtask" bsb22-vk "$vk_bin" "$vkey_dir" "${module}.rs"; then
        echo "vk codegen failed for $stem" >&2
        exit 1
    fi
done

{
    echo "mod aggregate;"
    echo "mod circuit;"
    echo "pub mod merge_chain;"
    echo "pub use aggregate::{AggregateCircuitId, InnerCircuitKind, MAX_AGGREGATE_BATCH, MIN_AGGREGATE_BATCH};"
    echo "pub use circuit::{Bsb22Commitment, CircuitId, OutputOwnerMode, RingP256ProofData};"
    echo '#[cfg(feature = "verifying-keys")]'
    echo "pub mod catalog;"
    echo '#[cfg(feature = "verifying-keys")]'
    echo "pub mod registry;"
    echo "pub mod registry_spec;"
    echo
    echo "$modules" | sort -u | while read -r module; do
        if [ -n "$module" ]; then
            echo '#[cfg(feature = "verifying-keys")]'
            echo "pub mod $module;"
        fi
    done
} >"$vkey_dir/mod.rs"

# The catalog is the single list every registry surface indexes. Regenerate it
# from the same module set so a new VK cannot miss it.
{
    echo "//! The full verifying-key catalog, one entry per generated module, sorted by"
    echo "//! module name (the \`mod.rs\` order). Registry codegen, the fingerprint pin,"
    echo "//! and the registry-spec table all index this array, so a new VK is added"
    echo "//! here exactly once."
    echo
    echo "use groth16_solana::groth16::Groth16Verifyingkey;"
    echo
    echo "use super::*;"
    echo
    # Two batched-merkle-tree VKs live outside this directory but inside the
    # catalog. They sort before every transfer/merge module name.
    module_count="$(echo "$modules" | sort -u | sed '/^$/d' | wc -l | tr -d ' ')"
    catalog_count="$((module_count + 2))"
    echo "macro_rules! catalog {"
    echo '    ($(($name:literal, $vk:expr),)*) => {'
    echo "        pub static VK_CATALOG: [(&str, &Groth16Verifyingkey<'static>); $catalog_count] = ["
    echo '            $(($name, $vk),)*'
    echo "        ];"
    echo "    };"
    echo "}"
    echo
    echo "catalog!("
    for batch in batch_address_append_40_10 batch_address_append_40_250; do
        echo "    ("
        echo "        \"$batch\","
        echo "        &zolana_batched_merkle_tree::verify::verifying_keys::$batch::VERIFYINGKEY"
        echo "    ),"
    done
    echo "$modules" | sort -u | while read -r module; do
        if [ -n "$module" ]; then
            echo "    (\"$module\", &$module::VERIFYINGKEY),"
        fi
    done
    echo ");"
} >"$vkey_dir/catalog.rs"

rustfmt "$vkey_dir"/*.rs

# Registry specs derive from the freshly committed VERIFYINGKEY consts.
(cd "$repo_root" && cargo run -q -p xtask -- vk-registry-consts)

echo "Regenerated verifying keys into $vkey_dir"
