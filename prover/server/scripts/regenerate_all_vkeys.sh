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

keys="$(find "$keys_dir" -maxdepth 1 -type f \( -name 'transfer_*.key' -o -name 'merge_*.key' \) | sort)"
if [ -z "$keys" ]; then
    echo "no transfer or merge proving keys in $keys_dir"
    exit 1
fi

modules=""
for key in $keys; do
    stem="$(basename "$key" .key)"
    module="${stem//-/_}"
    vk_bin="$tmp_dir/${stem}.vkbin"

    echo "exporting raw vk: $stem"
    if ! ./light-prover export-vk --keys-file "$key" --output "$vk_bin" >/dev/null; then
        echo "WARN: export-vk failed, skipping $stem"
        continue
    fi

    if "$xtask" bsb22-vk \
        "$vk_bin" "$vkey_dir" "${module}.rs"; then
        modules="${modules}${module}"$'\n'
    else
        echo "WARN: vk codegen failed, skipping $stem"
    fi
done

{
    echo "mod circuit;"
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

# The catalog is the single list every registry surface indexes; regenerate it
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
    # catalog; they sort before every transfer/merge module name.
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
