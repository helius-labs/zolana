# `phala envs update` replaces the whole sealed env, so release and ship both build it here.

# tee_env <registry host> fills TEE_ENV with -e arguments for the phala CLI.
tee_env() {
    : "${PROVER_API_KEY:?}"
    TEE_ENV=(
        -e "PROVER_API_KEY=$PROVER_API_KEY"
        -e "PROVER_INDEXER_API_KEY=${PROVER_INDEXER_API_KEY:-}"
        -e "PHOTON_RPC_URL=${PHOTON_RPC_URL:-}"
        -e "PHOTON_DUMP_URL=${PHOTON_DUMP_URL:-}"
        -e "PHOTON_DUMP_ID=${PHOTON_DUMP_ID:-}"
    )
    # Phala's pre-launch script logs in to the registry with these.
    if [[ -n ${TEE_REGISTRY_TOKEN:-} ]]; then
        TEE_ENV+=(
            -e "DSTACK_DOCKER_REGISTRY=$1"
            -e "DSTACK_DOCKER_USERNAME=${TEE_REGISTRY_USERNAME:?TEE_REGISTRY_USERNAME pairs with TEE_REGISTRY_TOKEN}"
            -e "DSTACK_DOCKER_PASSWORD=$TEE_REGISTRY_TOKEN"
        )
    fi
}
