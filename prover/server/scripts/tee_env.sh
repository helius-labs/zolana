# `phala envs update` replaces the whole sealed env, so release and ship both build it here.

# tee_env fills TEE_ENV with -e arguments for the phala CLI, logging in to TEE_REGISTRY_HOST.
tee_env() {
    : "${PROVER_API_KEY:?}"
    TEE_ENV=(
        -e "PROVER_API_KEY=$PROVER_API_KEY"
        -e "PROVER_INDEXER_API_KEY=${PROVER_INDEXER_API_KEY:-}"
        -e "PHOTON_RPC_URL=${PHOTON_RPC_URL:-}"
        -e "PHOTON_DUMP_URL=${PHOTON_DUMP_URL:-}"
        -e "PHOTON_DUMP_ID=${PHOTON_DUMP_ID:-}"
    )
    # Phala's pre-launch script tries Docker credentials before ECR, so only one set is sealed.
    if [[ -n ${TEE_AWS_ACCESS_KEY_ID:-} ]]; then
        [[ ${TEE_REGISTRY_HOST:-} =~ ^[0-9]+\.dkr\.ecr\.([a-z0-9-]+)\.amazonaws\.com$ ]] \
            || { echo "TEE_REGISTRY_HOST must be an ECR registry host" >&2; exit 1; }
        TEE_ENV+=(
            -e "DSTACK_AWS_ACCESS_KEY_ID=$TEE_AWS_ACCESS_KEY_ID"
            -e "DSTACK_AWS_SECRET_ACCESS_KEY=${TEE_AWS_SECRET_ACCESS_KEY:?TEE_AWS_SECRET_ACCESS_KEY pairs with TEE_AWS_ACCESS_KEY_ID}"
            -e "DSTACK_AWS_REGION=${BASH_REMATCH[1]}"
            -e "DSTACK_AWS_ECR_REGISTRY=$TEE_REGISTRY_HOST"
        )
    elif [[ -n ${TEE_REGISTRY_TOKEN:-} ]]; then
        TEE_ENV+=(
            -e "DSTACK_DOCKER_REGISTRY=${TEE_REGISTRY_HOST:?TEE_REGISTRY_HOST names the registry the token logs in to}"
            -e "DSTACK_DOCKER_USERNAME=${TEE_REGISTRY_USERNAME:?TEE_REGISTRY_USERNAME pairs with TEE_REGISTRY_TOKEN}"
            -e "DSTACK_DOCKER_PASSWORD=$TEE_REGISTRY_TOKEN"
        )
    fi
}
