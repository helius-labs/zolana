#!/usr/bin/env bash
set -euo pipefail

# Trusted setup for the squads proving systems, leg keys and folds.
#
# None of these are published, so every machine runs its own setup and gets its
# own verifying key. Every key therefore rewrites its committed constant in
# zones/squads/interface/src/verifying_keys/, including the proving-key checksum
# that pins the constant to that setup. The program must be rebuilt before it
# verifies that key's proofs.
#
# A fold compiles in its leg's verifying key, so a regenerated leg key
# invalidates every fold built from it. Both are made here in one pass for that
# reason.
#
# An existing key is kept, so a warm run costs a file check, but the verifying
# keys are exported unconditionally: a key on disk and the constant beside it
# must always be the same setup, and only exporting on generation would leave
# them apart after an interrupted run. Each setup writes to a temporary file and
# is moved into place only once it finished, so an interrupted run never leaves
# a truncated key a later run would take for a finished one.

script="$(cd "$(dirname "$0")" && pwd)/$(basename "$0")"
keys_dir="${1:-$(dirname "$script")/../proving-keys}"
mkdir -p "$keys_dir"
keys_dir="$(cd "$keys_dir" && pwd)"

cd "$(dirname "$0")/.."
repo_root="$(cd ../.. && pwd)"
vkey_dir="$repo_root/zones/squads/interface/src/verifying_keys"

# Squads zone circuit shapes: (1,1) withdrawal and (2,2) transfer.
# Mirrors zoneSupportedShapes in prover/common/lazy_key_manager.go.
zone_shapes=(
    "1 1"
    "2 2"
)

# Squads key encryption recipient-count set (recovery + auditor).
# Mirrors keyEncryptionSupportedKeys in prover/common/lazy_key_manager.go.
key_encryption_keys=(1 2 3)

# Leg counts with a fold key. Mirrors foldSupportedLegs.
fold_legs=(2 3)

# Zone leg shapes a fold covers. Mirrors zoneFoldSupportedShapes. Only the
# transfer shape folds, a withdrawal already spends the whole balance.
zone_fold_shapes=(
    "2 2"
)

# Recipients per key-encryption fold leg. Mirrors
# keyEncryptionFoldSupportedKeys.
key_encryption_fold_keys=(3)

go build -o light-prover .
(cd "$repo_root" && cargo build -q -p xtask)
xtask="$repo_root/target/debug/xtask"

tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

# The catalogue as "<key stem> <verifying-key module>" pairs, in setup order.
# Every leg key comes before the folds compiled against it.
catalogue=()
for shape in "${zone_shapes[@]}"; do
    read -r n_inputs n_outputs <<<"$shape"
    catalogue+=("squads_zone_${n_inputs}_${n_outputs} zone_${n_inputs}_${n_outputs}")
done
for num_keys in "${key_encryption_keys[@]}"; do
    catalogue+=("squads_key_encryption_${num_keys} key_encryption_${num_keys}")
done
for shape in "${zone_fold_shapes[@]}"; do
    read -r n_inputs n_outputs <<<"$shape"
    for legs in "${fold_legs[@]}"; do
        catalogue+=("squads_zone_fold_${n_inputs}_${n_outputs}_l${legs} zone_fold_${n_inputs}_${n_outputs}_l${legs}")
    done
done
for keys_per_leg in "${key_encryption_fold_keys[@]}"; do
    for legs in "${fold_legs[@]}"; do
        catalogue+=("squads_key_encryption_fold_${keys_per_leg}_l${legs} key_encryption_fold_${keys_per_leg}_l${legs}")
    done
done

setup() {
    local stem="$1"
    local output="${keys_dir}/${stem}.key"
    if [[ -f "$output" ]]; then
        return
    fi
    echo "Generating ${stem}"
    case "$stem" in
    squads_zone_fold_*)
        [[ "$stem" =~ ^squads_zone_fold_([0-9]+)_([0-9]+)_l([0-9]+)$ ]]
        ./light-prover setup-zone-fold \
            --inner-keys-file "${keys_dir}/squads_zone_${BASH_REMATCH[1]}_${BASH_REMATCH[2]}.key" \
            --legs "${BASH_REMATCH[3]}" \
            --output "$output.partial"
        ;;
    squads_key_encryption_fold_*)
        [[ "$stem" =~ ^squads_key_encryption_fold_([0-9]+)_l([0-9]+)$ ]]
        ./light-prover setup-key-encryption-fold \
            --inner-keys-file "${keys_dir}/squads_key_encryption_${BASH_REMATCH[1]}.key" \
            --legs "${BASH_REMATCH[2]}" \
            --output "$output.partial"
        ;;
    squads_zone_*)
        [[ "$stem" =~ ^squads_zone_([0-9]+)_([0-9]+)$ ]]
        ./light-prover setup-zone \
            --n-inputs "${BASH_REMATCH[1]}" \
            --n-outputs "${BASH_REMATCH[2]}" \
            --output "$output.partial"
        ;;
    squads_key_encryption_*)
        [[ "$stem" =~ ^squads_key_encryption_([0-9]+)$ ]]
        ./light-prover setup-key-encryption \
            --num-keys "${BASH_REMATCH[1]}" \
            --output "$output.partial"
        ;;
    *)
        echo "no setup command for $stem" >&2
        exit 1
        ;;
    esac
    mv "$output.partial" "$output"
}

for entry in "${catalogue[@]}"; do
    read -r stem _ <<<"$entry"
    setup "$stem"
done

modules=()
for entry in "${catalogue[@]}"; do
    read -r stem module <<<"$entry"
    ./light-prover export-vk \
        --keys-file "${keys_dir}/${stem}.key" \
        --output "$tmp_dir/$module.vkbin" >/dev/null
    "$xtask" bsb22-vk \
        "$tmp_dir/$module.vkbin" \
        "$vkey_dir" \
        "$module.rs" \
        "${keys_dir}/${stem}.key"
    modules+=("$module")
done

paths=()
for module in "${modules[@]}"; do
    paths+=("$vkey_dir/$module.rs")
done
rustfmt --edition 2021 "${paths[@]}"

printf 'pub mod %s;\n' "${modules[@]}" | sort >"$vkey_dir/mod.rs"

echo "rewrote ${#modules[@]} verifying-key constants, rebuild the programs before proving"
echo "Done. Squads proving keys in ${keys_dir}"
