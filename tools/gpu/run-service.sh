#!/usr/bin/env bash
set -euo pipefail
deployment=$1
service=$2
set -a
# 1. Deployment files are trusted operator input.
# shellcheck source=/dev/null
source "$deployment/deployment.env"
set +a
case "$service" in
    photon)
        export TOKIO_WORKER_THREADS=${TOKIO_WORKER_THREADS:-2}
        exec "$deployment/current/photon" --port "${PHOTON_PORT:-8784}" \
            --rpc-url "$PHOTON_RPC_URL" --db-url "$DATABASE_URL" \
            --max-db-conn "${PHOTON_DB_CONNECTIONS:-20}" \
            --max-concurrent-block-fetches "${PHOTON_BLOCK_FETCHES:-10}" --logging-format json
        ;;
    prover)
        export PROVER_BACKEND=aeglos GOMAXPROCS=${GOMAXPROCS:-6}
        export PROVER_TRANSFER_CONCURRENCY=${PROVER_TRANSFER_CONCURRENCY:-2}
        export PROVER_REQUEST_TIMING=${PROVER_REQUEST_TIMING:-true}
        args=(start --require-optimized-build --server-only \
            --keys-dir "$deployment/keys" --preload-keys none \
            --prover-address "${PROVER_ADDRESS:-127.0.0.1:3003}" \
            --metrics-address "${PROVER_METRICS_ADDRESS:-127.0.0.1:9997}" \
            --indexer-url "http://127.0.0.1:${PHOTON_PORT:-8784}")
        if [[ -n ${PROVER_PRELOAD_CIRCUITS:-} ]]; then
            args+=(--preload-circuits "$PROVER_PRELOAD_CIRCUITS")
        fi
        exec "$deployment/current/light-prover" "${args[@]}"
        ;;
    *) echo 'Unknown service' >&2; exit 1 ;;
esac
