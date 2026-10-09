#!/bin/sh
set -eu
PATH=/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/bin

parent_cid=3
# Holds every served key plus the largest partial download.
keys_mib=14336

# Any child exit ends the enclave for the parent to restart.
trap 'exit 1' USR1
watch() {
    "$@" || true
    kill -USR1 $$
}

ip link set lo up
mount -t tmpfs -o "size=${keys_mib}m,mode=0700,uid=65532,gid=65532" proving-keys /proving-keys
chown 65532:65532 /dev/nsm

# TLS to these names terminates in the enclave.
printf '127.0.0.1 localhost\n' > /etc/hosts
while read -r address host port vsock; do
    printf '%s %s\n' "$address" "$host" >> /etc/hosts
    watch socat "TCP-LISTEN:$port,bind=$address,fork,reuseaddr" "VSOCK-CONNECT:$parent_cid:$vsock" &
done < /etc/zolana-nitro/routes
watch socat VSOCK-LISTEN:3001,fork,reuseaddr TCP:127.0.0.1:3001 &

memory_mib=$(awk '/^MemTotal:/ { print int($2 / 1024) }' /proc/meminfo)
heap_mib=$((memory_mib - keys_mib - 2048))
[ "$heap_mib" -ge 8192 ] || { echo "enclave memory ${memory_mib} MiB is too small" >&2; exit 1; }

concurrency=$(cat /etc/zolana-nitro/concurrency)
export PROVER_SYNC_CONCURRENCY="$concurrency"
set -- start --require-optimized-build --server-only --auto-download --preload-keys none \
    --keys-dir /proving-keys --prover-address 127.0.0.1:3001 --metrics-address 127.0.0.1:9998 \
    --tee nitro --transfer-concurrency "$concurrency" \
    --serve 'transfer_*' --serve 'merge_*' --serve 'custom_ring_*'
indexer=$(cat /etc/zolana-nitro/indexer-url)
[ -z "$indexer" ] || set -- "$@" --indexer-url "$indexer"
export GOMEMLIMIT="${heap_mib}MiB"
watch su-exec 65532:65532 light-prover "$@" &
wait
exit 1
