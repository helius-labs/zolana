#!/usr/bin/env bash
set -euo pipefail
[[ $(id -u) == 0 ]]
bundle=$1
provider=$2
[[ $provider == vast || $provider == ec2 ]]
for tool in supervisorctl supervisord psql pg_restore curl nvidia-smi python3; do
    command -v "$tool" >/dev/null
done
(cd "$bundle" && sha256sum -c SHA256SUMS)
"$bundle/light-prover" --version >/dev/null
"$bundle/photon" --version >/dev/null
set -a
# 1. Deployment files are trusted operator input.
# shellcheck source=/dev/null
source "$bundle/deployment.env"
set +a
[[ ${DEPLOYMENT_NAME:-} =~ ^[a-z][a-z0-9_]{0,23}$ ]]
: "${PHOTON_RPC_URL:?Set PHOTON_RPC_URL}"
: "${DATABASE_URL:?Set DATABASE_URL}"
unset PGHOST PGHOSTADDR PGPORT PGDATABASE PGUSER PGSERVICE PGSERVICEFILE PGOPTIONS
python3 "$bundle/validate.py" > "$bundle/database.identity"
capability=$(nvidia-smi --query-gpu=compute_cap --format=csv,noheader | head -n 1)
[[ $(cat "$bundle/cuda-arch") == "sm_${capability//./}" ]]
revision=$(cat "$bundle/source-revision")
[[ $revision =~ ^[0-9a-f]{40}$ ]]
deployment="/opt/zolana-gpu/$DEPLOYMENT_NAME"
if [[ -d $deployment && ! -f $deployment/managed ]]; then
    echo 'Refusing an unmanaged deployment directory' >&2
    exit 1
fi
if [[ -f $deployment/managed ]]; then
    cmp "$bundle/database.identity" "$deployment/database.identity"
fi
if [[ ! -f $deployment/managed ]]; then
    # 2. First deployment requires a dedicated empty local database.
    objects=$(psql "$DATABASE_URL" -XAt -v ON_ERROR_STOP=1 -c "SELECT count(*) FROM (SELECT relnamespace AS namespace FROM pg_class UNION ALL SELECT pronamespace FROM pg_proc UNION ALL SELECT typnamespace FROM pg_type UNION ALL SELECT oid FROM pg_namespace WHERE nspname <> 'public') objects JOIN pg_namespace n ON n.oid = objects.namespace WHERE left(n.nspname, 3) <> 'pg_' AND n.nspname <> 'information_schema'")
    [[ $objects == 0 ]]
elif [[ -f $bundle/cache.dump ]]; then
    echo 'Refusing to restore a cache over an existing deployment' >&2
    exit 1
fi
if [[ -f $bundle/cache.dump ]]; then
    timeout 300s pg_restore --single-transaction --no-owner --no-privileges --exit-on-error \
        --dbname="$DATABASE_URL" "$bundle/cache.dump"
fi
id zolana_gpu >/dev/null 2>&1 || useradd --system --home-dir /nonexistent --shell /usr/sbin/nologin zolana_gpu
install -d -m 0750 -o root -g zolana_gpu "$deployment" "$deployment/releases"
install -d -m 0750 -o zolana_gpu -g zolana_gpu "$deployment/keys" "$deployment/logs"
release="$deployment/releases/$revision"
if [[ -d $release ]]; then
    cmp "$bundle/SHA256SUMS" "$release/SHA256SUMS"
else
    install -d -m 0750 -o root -g zolana_gpu "$release"
    install -m 0755 "$bundle/light-prover" "$bundle/photon" "$bundle/run-service.sh" "$release/"
    install -m 0644 "$bundle/SHA256SUMS" "$bundle/aeglos-source.lock" "$bundle/source-revision" "$bundle/cuda-arch" "$bundle/LICENSE" "$bundle/THIRD_PARTY_NOTICES" "$bundle/install.sh" "$bundle/supervisord.conf" "$bundle/validate.py" "$release/"
fi
install -m 0640 -o root -g zolana_gpu "$bundle/deployment.env" "$deployment/deployment.env"
install -m 0600 "$bundle/database.identity" "$deployment/database.identity"
install -m 0600 "$bundle/supervisord.conf" "$deployment/supervisord.conf"
ln -sfn "$release" "$deployment/current.next"
mv -Tf "$deployment/current.next" "$deployment/current"
touch "$deployment/managed"
if [[ $provider == ec2 ]]; then
    cat > "/etc/systemd/system/zolana-gpu-$DEPLOYMENT_NAME.service" <<EOF
[Unit]
Description=Zolana GPU prover and indexer
After=network-online.target postgresql.service
Wants=network-online.target
[Service]
Type=forking
PIDFile=$deployment/supervisor.pid
ExecStart=/usr/bin/supervisord -c $deployment/supervisord.conf
ExecStop=/usr/bin/supervisorctl -c $deployment/supervisord.conf shutdown
Restart=on-failure
TimeoutStopSec=120
[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable --now "zolana-gpu-$DEPLOYMENT_NAME.service"
fi
if supervisorctl -c "$deployment/supervisord.conf" pid >/dev/null 2>&1; then
    supervisorctl -c "$deployment/supervisord.conf" reread
    supervisorctl -c "$deployment/supervisord.conf" update
    supervisorctl -c "$deployment/supervisord.conf" restart photon prover
else
    supervisord -c "$deployment/supervisord.conf"
fi
for service in "http://127.0.0.1:${PHOTON_PORT:-8784}/readiness" "http://${PROVER_ADDRESS:-127.0.0.1:3003}/ready"; do
    ready=false
    for ((attempt=0; attempt<60; attempt++)); do
        if curl -fsS --max-time 2 "$service" >/dev/null 2>&1; then
            ready=true
            break
        fi
        sleep 1
    done
    if [[ $ready == false ]]; then
        echo 'Service readiness failed, inspect the deployment logs' >&2
        exit 1
    fi
done
supervisorctl -c "$deployment/supervisord.conf" status
