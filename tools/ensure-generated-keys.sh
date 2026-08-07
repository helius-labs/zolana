#!/usr/bin/env bash
set -euo pipefail

# Run one of the unpublished-key generators without leaving the committed
# verifying-key constants rewritten.
#
# A generator exports a constant for every key on disk, not only for the keys it
# sampled, so a warm run rewrites the committed constants with no new setup
# behind them. `program-libs/interface/tests/vk_fingerprint.rs` hashes those
# constants, so that rewrite fails the next tier. A run that created no key
# sampled no toxic waste, so its rewrite is reverted here. A cold run keeps it,
# because the constant must match the key that was just sampled.
#
# Files already modified before the run are left alone.

usage() {
    echo "usage: $0 <generator-script> <keys-dir> <verifying-key-dir>" >&2
    exit 2
}

[ $# -eq 3 ] || usage
generator=$1
keys_dir=$2
vkey_dir=$3

[ -x "$generator" ] || { echo "not executable: $generator" >&2; exit 1; }
[ -d "$vkey_dir" ] || { echo "no such directory: $vkey_dir" >&2; exit 1; }

key_list() {
    [ -d "$keys_dir" ] || return 0
    find "$keys_dir" -maxdepth 1 -name '*.key' | sort
}

# Untracked files are skipped, because `git checkout` cannot restore what git
# does not know, and a new module belongs to a key that was just sampled.
dirty_list() {
    git status --porcelain -- "$vkey_dir" | awk '$1 != "??" { print $NF }' | sort
}

keys_before=$(key_list)
dirty_before=$(dirty_list)

"$generator" "$keys_dir"

if [ "$(key_list)" != "$keys_before" ]; then
    exit 0
fi

while IFS= read -r path; do
    [ -z "$path" ] && continue
    printf '%s\n' "$dirty_before" | grep -qxF "$path" && continue
    git checkout -- "$path"
done <<EOF
$(dirty_list)
EOF
