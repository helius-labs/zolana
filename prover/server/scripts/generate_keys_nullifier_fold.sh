#!/usr/bin/env bash
set -euo pipefail

# Trusted setup for the nullifier fold proving systems.
#
# The keys here match the fold verifying-key modules in
# program-libs/batched-merkle-tree/src/verify/verifying_keys/. They are not
# published, so every machine generates its own.
#
# Groth16 setup samples fresh toxic waste, so a regenerated key carries a
# different verifying key. Each generated key therefore rewrites its committed
# constant, and the program must be rebuilt before it verifies that key's
# proofs.
#
# Idempotent. An existing key is kept, so a warm run costs a file check.
#
# Set ZOLANA_AGGREGATE_NO_AUTOGEN=1 to fail with the missing names instead of
# generating.

script="$(cd "$(dirname "$0")" && pwd)/$(basename "$0")"

# Resolved against the caller's directory, before the cd below moves it.
keys_dir="${1:-$(dirname "$script")/../proving-keys}"
mkdir -p "$keys_dir"
keys_dir="$(cd "$keys_dir" && pwd)"

cd "$(dirname "$0")/.."
repo_root="$(cd ../.. && pwd)"
vkey_dir="$repo_root/program-libs/batched-merkle-tree/src/verify/verifying_keys"

# "<tree height> <inner batch size> <run>". Only the address-append circuit is
# folded, the forester's only sequential path.
folds=(
    "40 10 2"
)

# Key size in MiB and setup seconds, measured on 16 cores.
estimate() {
    case "$1" in
    2) echo "405 90" ;;
    *) echo "630 152" ;;
    esac
}

missing=()
missing_mib=0
missing_s=0
for entry in "${folds[@]}"; do
    read -r height batch run <<<"$entry"
    output="$keys_dir/nullifier-fold_${height}_${batch}_r${run}.key"
    if [[ -f "$output" ]]; then
        continue
    fi
    read -r mib seconds <<<"$(estimate "$run")"
    missing+=("$(basename "$output")")
    missing_mib=$((missing_mib + mib))
    missing_s=$((missing_s + seconds))
done

if ((${#missing[@]} > 0)) && [[ "${ZOLANA_AGGREGATE_NO_AUTOGEN:-}" == "1" ]]; then
    echo "missing nullifier fold keys in $keys_dir" >&2
    printf '  %s\n' "${missing[@]}" >&2
    echo "generate them with $script $keys_dir" >&2
    exit 1
fi

if ((${#missing[@]} > 0)); then
    # Fail before a long setup rather than partway through one.
    free_mib=$(df -Pk "$keys_dir" | awk 'NR == 2 { print int($4 / 1024) }')
    if ((free_mib < missing_mib)); then
        echo "$keys_dir needs $missing_mib MiB free, has $free_mib MiB" >&2
        exit 1
    fi

    echo "generating ${#missing[@]} nullifier fold keys, about $missing_mib MiB and $((missing_s / 60 + 1)) minutes on 16 cores"
    printf '  %s\n' "${missing[@]}"
    echo "missing append keys are downloaded first"
fi

go build -o light-prover .
(cd "$repo_root" && cargo build -q -p xtask)
xtask="$repo_root/target/debug/xtask"

tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT
regenerated=()

# The export runs for every key, generated now or already on disk. Rewriting
# only what this run generated would leave a warm run's constant pinned to
# whatever key the last cold run produced, and the two would verify nothing.
for entry in "${folds[@]}"; do
    read -r height batch run <<<"$entry"
    output="$keys_dir/nullifier-fold_${height}_${batch}_r${run}.key"

    if [[ ! -f "$output" ]]; then
        inner_name="batch_address-append_${height}_${batch}.key"
        inner_key="$keys_dir/$inner_name"

        # setup-nullifier-fold rejects an inner key that does not match the
        # lockfile, so fetch the pinned one rather than generating a divergent key.
        if [[ ! -f "$inner_key" ]]; then
            echo "fetching inner key $inner_name"
            ./light-prover download --keys-dir "$keys_dir" --key "$inner_name"
        fi

        echo "setting up $output"
        ./light-prover setup-nullifier-fold \
            --inner-keys-file "$inner_key" \
            --run "$run" \
            --output "$output.partial"
        mv "$output.partial" "$output"
    fi

    module="nullifier_fold_${height}_${batch}_r${run}"
    ./light-prover export-vk --keys-file "$output" --output "$tmp_dir/$module.vkbin" >/dev/null
    "$xtask" bsb22-vk "$tmp_dir/$module.vkbin" "$vkey_dir" "$module.rs"
    regenerated+=("$vkey_dir/$module.rs")
done

rustfmt "${regenerated[@]}"
echo "rewrote ${#regenerated[@]} verifying-key constants, rebuild the programs before proving"
