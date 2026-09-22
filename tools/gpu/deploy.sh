#!/usr/bin/env bash
set -euo pipefail
if [[ $# -lt 4 || $# -gt 5 || $1 == --help ]]; then
    echo "Usage: $0 vast|ec2 SSH_TARGET BUNDLE_DIRECTORY ENV_FILE [CACHE_DUMP]"
    exit 0
fi
case "$1" in
    vast) remote_runner=bash ;;
    ec2) remote_runner='sudo -n bash' ;;
    *) echo 'Expected vast or ec2' >&2; exit 1 ;;
esac
target=$2
bundle=$(cd "$3" && pwd)
env_file=$4
[[ $target != -* && -f $env_file ]]
ssh_options=(-o BatchMode=yes -o ConnectTimeout=10 -p "${SSH_PORT:-22}")
scp_options=(-o BatchMode=yes -o ConnectTimeout=10 -P "${SSH_PORT:-22}")
if [[ -n ${SSH_KEY:-} ]]; then
    ssh_options+=(-i "$SSH_KEY" -o IdentitiesOnly=yes)
    scp_options+=(-i "$SSH_KEY" -o IdentitiesOnly=yes)
fi
scratch=$(mktemp -d)
remote=''
cleanup() {
    rm -rf "$scratch"
    if [[ -n $remote ]]; then
        cleanup_command="rm -rf -- '$remote'"
        printf '%s\n' "$cleanup_command" | ssh "${ssh_options[@]}" "$target" bash >/dev/null 2>&1 || true
    fi
}
trap cleanup EXIT
tar -czf "$scratch/bundle.tar.gz" -C "$bundle" light-prover photon SHA256SUMS aeglos-source.lock source-revision cuda-arch LICENSE THIRD_PARTY_NOTICES \
    install.sh run-service.sh supervisord.conf validate.py
remote=$(ssh "${ssh_options[@]}" "$target" 'umask 077; mktemp -d /tmp/zolana-gpu.XXXXXXXX')
[[ $remote =~ ^/tmp/zolana-gpu\.[a-zA-Z0-9]+$ ]]
scp "${scp_options[@]}" "$scratch/bundle.tar.gz" "$target:$remote/bundle.tar.gz"
scp "${scp_options[@]}" "$env_file" "$target:$remote/deployment.env"
if [[ $# == 5 ]]; then
    scp "${scp_options[@]}" "$5" "$target:$remote/cache.dump"
fi
install_command="tar -xzf '$remote/bundle.tar.gz' -C '$remote' && cd '$remote' && sha256sum -c SHA256SUMS && $remote_runner '$remote/install.sh' '$remote' '$1'"
printf '%s\n' "$install_command" | ssh "${ssh_options[@]}" "$target" bash
