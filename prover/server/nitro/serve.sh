#!/bin/sh
set -eu

case ${1-} in
    client) keys_mib=22528; set -- 'transfer_*' 'merge_*' 'custom_ring_*' ;;
    rings) keys_mib=19456; set -- 'transfer_ring_*' 'transfer_eddsa_ring_*' 'merge_ring_*' 'custom_ring_*' ;;
    *) echo "SERVE must be client or rings" >&2; exit 1 ;;
esac
printf '%s\n' "$keys_mib" "$@"
