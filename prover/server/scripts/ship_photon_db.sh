#!/usr/bin/env bash
set -euo pipefail

usage() {
    echo "usage: $0 <cvm-name> --dump-url <https-url>" >&2
    exit 1
}
[[ $# -eq 3 && $2 == --dump-url && $3 =~ ^https:// ]] || usage
name=$1
export PHOTON_DUMP_URL=$3
: "${PHALA_KEY:?}" "${PROVER_API_KEY:?}"

here=$(cd "$(dirname "$0")" && pwd)
# shellcheck source=tee_env.sh
source "$here/tee_env.sh"
: "${TEE_REGISTRY_HOST:?TEE_REGISTRY_HOST names the registry the CVM pulls from}"
tee_env
npx -y phala@1.1.22 envs update "$name" --api-key "$PHALA_KEY" "${TEE_ENV[@]}"
npx -y phala@1.1.22 cvms restart "$name" --api-key "$PHALA_KEY"
echo "restart requested, restore requires the snapshot digest pinned in the compose"
