#!/usr/bin/env bash
set -euo pipefail

# Trusted setup for the outer proving systems: aggregate batches and merge
# chains.
#
# Every key here matches a verifying-key module in
# program-libs/interface/src/verifying_keys/. They are not published, so every
# machine generates its own.
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
vkey_dir="$repo_root/program-libs/interface/src/verifying_keys"

# "<inner key stem> <shape>" for the rails the shielded pool can settle as a
# batch. Merge is excluded, it has no aggregate instruction. Ring-authority is
# excluded, is_supported() rejects it.
inner_keys=(
    "transfer_confidential 2 2"
    "transfer_confidential 2 3"
    "transfer_ring 2 3"
    "transfer_p256_ring 2 3"
)

# Batch sizes with a registered verifying key. is_supported() caps at 3.
batches=(2 3)

# Merge chain level shapes: legs per level, bottom level first, top level 1. The
# tree-backed inputs a shape collapses is 7*legs+1, and each of them puts a
# nullifier and two root indices on the wire, so the transaction bounds the list
# well before the circuit does.
merge_chains=(
    "1 1"
    "2 1"
)

# Key size in MiB and setup seconds, measured on 16 cores. Outer cost follows
# the inner public input and commitment counts, so every non-P256 rail matches.
estimate() {
    case "$1:$2" in
    transfer_p256_ring:2) echo "734 170" ;;
    transfer_p256_ring:3) echo "1011 282" ;;
    *:2) echo "404 101" ;;
    *:3) echo "630 152" ;;
    esac
}

# Key size in MiB and setup seconds for a chain, keyed by leg count.
chain_estimate() {
    case "$1" in
    2) echo "404 101" ;;
    *) echo "630 152" ;;
    esac
}

chain_name() {
    echo "${1// /_}"
}

missing=()
missing_mib=0
missing_s=0
for entry in "${inner_keys[@]}"; do
    read -r stem n_in n_out <<<"$entry"
    for batch in "${batches[@]}"; do
        output="$keys_dir/aggregate_${stem}_${n_in}_${n_out}_b${batch}.key"
        if [[ -f "$output" ]]; then
            continue
        fi
        read -r mib seconds <<<"$(estimate "$stem" "$batch")"
        missing+=("$(basename "$output")")
        missing_mib=$((missing_mib + mib))
        missing_s=$((missing_s + seconds))
    done
done

for levels in "${merge_chains[@]}"; do
    output="$keys_dir/merge-chain_$(chain_name "$levels").key"
    if [[ -f "$output" ]]; then
        continue
    fi
    read -r mib seconds <<<"$(chain_estimate "$(wc -w <<<"$levels")")"
    missing+=("$(basename "$output")")
    missing_mib=$((missing_mib + mib))
    missing_s=$((missing_s + seconds))
done

if ((${#missing[@]} > 0)) && [[ "${ZOLANA_AGGREGATE_NO_AUTOGEN:-}" == "1" ]]; then
    echo "missing outer keys in $keys_dir" >&2
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

    echo "generating ${#missing[@]} outer keys, about $missing_mib MiB and $((missing_s / 60)) minutes on 16 cores"
    printf '  %s\n' "${missing[@]}"
    echo "missing inner keys are downloaded first"
fi
echo "verifying-key constants in $vkey_dir are rewritten from the keys on disk"

go build -o light-prover .
(cd "$repo_root" && cargo build -q -p xtask)
xtask="$repo_root/target/debug/xtask"

tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

# The export below runs for every key, generated now or already on disk.
# Rewriting only what this run generated would leave a warm run's constant
# pinned to whatever key the last cold run produced.
regenerated=()

for entry in "${inner_keys[@]}"; do
    read -r stem n_in n_out <<<"$entry"
    todo=()
    for batch in "${batches[@]}"; do
        output="$keys_dir/aggregate_${stem}_${n_in}_${n_out}_b${batch}.key"
        [[ -f "$output" ]] || todo+=("$batch")
    done

    inner_name="${stem}_${n_in}_${n_out}.key"
    inner_key="$keys_dir/$inner_name"

    # setup-aggregate rejects an inner key that does not match the lockfile, so
    # fetch the pinned one rather than generating a divergent key locally.
    if ((${#todo[@]} > 0)) && [[ ! -f "$inner_key" ]]; then
        echo "fetching inner key $inner_name"
        ./light-prover download --keys-dir "$keys_dir" --key "$inner_name"
    fi

    for batch in "${batches[@]}"; do
        output="$keys_dir/aggregate_${stem}_${n_in}_${n_out}_b${batch}.key"
        if [[ ! -f "$output" ]]; then
            echo "setting up $output"
            ./light-prover setup-aggregate \
                --inner-keys-file "$inner_key" \
                --batch "$batch" \
                --output "$output.partial"
            mv "$output.partial" "$output"
        fi

        module="$(basename "$output" .key)"
        ./light-prover export-vk --keys-file "$output" --output "$tmp_dir/$module.vkbin" >/dev/null
        "$xtask" bsb22-vk "$tmp_dir/$module.vkbin" "$vkey_dir" "$module.rs"
        regenerated+=("$vkey_dir/$module.rs")
    done
done

merge_key="$keys_dir/merge_8_1.key"
for levels in "${merge_chains[@]}"; do
    output="$keys_dir/merge-chain_$(chain_name "$levels").key"

    if [[ ! -f "$output" ]]; then
        # setup-merge-chain rejects a merge key that does not match the lockfile,
        # so fetch the pinned one rather than generating a divergent key locally.
        if [[ ! -f "$merge_key" ]]; then
            echo "fetching inner key merge_8_1.key"
            ./light-prover download --keys-dir "$keys_dir" --key merge_8_1.key
        fi

        echo "setting up $output"
        level_flags=()
        for n in $levels; do
            level_flags+=(--levels "$n")
        done
        ./light-prover setup-merge-chain \
            --inner-keys-file "$merge_key" \
            "${level_flags[@]}" \
            --output "$output.partial"
        mv "$output.partial" "$output"
    fi

    module="merge_chain_$(chain_name "$levels")"
    ./light-prover export-vk --keys-file "$output" --output "$tmp_dir/$module.vkbin" >/dev/null
    "$xtask" bsb22-vk "$tmp_dir/$module.vkbin" "$vkey_dir" "$module.rs"
    regenerated+=("$vkey_dir/$module.rs")
done

rustfmt "${regenerated[@]}"
echo "rewrote ${#regenerated[@]} verifying-key constants, rebuild the programs before proving"
