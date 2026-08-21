#!/usr/bin/env bash
# Stand up an isolated test deployment of the prover and one ring RPC on ECS.
# Every resource is named zolana-rings-test-* and tagged zolana-rings-test=1,
# nothing it creates is shared with another deployment.
#
#   tools/rings-test-deploy.sh up              create and start from published images
#   tools/rings-test-deploy.sh status          addresses and health
#   tools/rings-test-deploy.sh down            delete everything it created
#
# Images live in the zolana-prover and zolana-ring-rpc repositories under
# <service>-<branch>-<sha12>, built and pushed here when the tag is absent.
# The prover task fetches the proving keys at start and converts the audit key
# itself. The ring RPC runs in derived mode, one root secret serves every ring
# that takes its auditor key from it at `init`. Both services sit behind one
# network load balancer, its DNS name is stable across task replacements.
#
# Needs aws (with write access), docker, jq, openssl, git.
#
# Environment
#   RINGS_TEST_PROVER_TAG     tag in zolana-prover, default prover-<branch>-<sha12>
#   RINGS_TEST_RING_RPC_TAG   tag in zolana-ring-rpc, default ring-rpc-<branch>-<sha12>
#   RINGS_TEST_INDEXER_URL    photon the ring RPC reads, required
#   RINGS_TEST_SOLANA_RPC_URL default https://api.devnet.solana.com
#   AWS_REGION            default eu-north-1
#   RINGS_TEST_VPC        VPC id, default the account's default VPC
#   RINGS_TEST_ORIGINS    browser origins for the ring RPC, default http://localhost:3000
#   RINGS_TEST_RP_ID      WebAuthn relying party id, default localhost
set -euo pipefail

usage() {
    sed -n '2,28p' "$0" | sed 's/^# \{0,1\}//' >&2
    exit 2
}

[[ $# -ge 1 ]] || usage
command="$1"
shift

root="$(git rev-parse --show-toplevel)"
cd "$root"
region="${AWS_REGION:-eu-north-1}"
prefix="zolana-rings-test"
tag_spec="Key=$prefix,Value=1"
ecs_tag_spec="key=$prefix,value=1"
account="$(aws sts get-caller-identity --query Account --output text)"
registry="$account.dkr.ecr.$region.amazonaws.com"
sha="$(git rev-parse HEAD)"
branch="$(git rev-parse --abbrev-ref HEAD | tr -c 'A-Za-z0-9._\n' '-')"
cluster="$prefix"
role="$prefix-exec"
log_group="/$prefix"
secret="$prefix/root-secret"
security_group="$prefix-sg"
load_balancer="$prefix"
prover_port=3001
ring_rpc_port=8785
redis_image="public.ecr.aws/docker/library/redis:7.4.4-alpine3.21"
fetch_image="public.ecr.aws/docker/library/alpine:3.21"
keys_release="https://github.com/helius-labs/zolana/releases/download/custom-ring-keys-v1"
published_keys="https://d3gbdb0egjwcw9.cloudfront.net/proving-keys/a5ff0c508cac3f51"

aws_() { aws --region "$region" "$@"; }

log() { printf '%s\n' "$*" >&2; }

ensure_repository() {
    aws_ ecr describe-repositories --repository-names "$1" >/dev/null 2>&1 \
        || aws_ ecr create-repository --repository-name "$1" --image-tag-mutability IMMUTABLE --tags "$tag_spec" >/dev/null
}

vpc_and_subnets() {
    local vpc="${RINGS_TEST_VPC:-}"
    if [[ -z "$vpc" ]]; then
        vpc="$(aws_ ec2 describe-vpcs --filters Name=is-default,Values=true --query 'Vpcs[0].VpcId' --output text)"
    fi
    [[ "$vpc" != None && -n "$vpc" ]] || { log "no default VPC, set RINGS_TEST_VPC"; exit 1; }
    subnets="$(aws_ ec2 describe-subnets --filters "Name=vpc-id,Values=$vpc" "Name=map-public-ip-on-launch,Values=true" \
        --query 'Subnets[].SubnetId' --output text | tr '\t' ',')"
    [[ -n "$subnets" ]] || { log "VPC $vpc has no public subnets"; exit 1; }
    echo "$vpc" "$subnets"
}

ensure_security_group() {
    local vpc="$1" id
    id="$(aws_ ec2 describe-security-groups --filters "Name=group-name,Values=$security_group" "Name=vpc-id,Values=$vpc" \
        --query 'SecurityGroups[0].GroupId' --output text)"
    if [[ "$id" == None || -z "$id" ]]; then
        id="$(aws_ ec2 create-security-group --group-name "$security_group" --description "$prefix" --vpc-id "$vpc" \
            --tag-specifications "ResourceType=security-group,Tags=[{$tag_spec}]" --query GroupId --output text)"
        for port in $prover_port $ring_rpc_port; do
            aws_ ec2 authorize-security-group-ingress --group-id "$id" --protocol tcp --port "$port" --cidr 0.0.0.0/0 >/dev/null
        done
    fi
    echo "$id"
}

ensure_role() {
    if ! aws_ iam get-role --role-name "$role" >/dev/null 2>&1; then
        aws_ iam create-role --role-name "$role" --tags "$tag_spec" --assume-role-policy-document '{
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Principal": {"Service": "ecs-tasks.amazonaws.com"}, "Action": "sts:AssumeRole"}]
        }' >/dev/null
        aws_ iam attach-role-policy --role-name "$role" \
            --policy-arn arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy
        aws_ iam put-role-policy --role-name "$role" --policy-name secrets --policy-document "{
            \"Version\": \"2012-10-17\",
            \"Statement\": [{\"Effect\": \"Allow\", \"Action\": \"secretsmanager:GetSecretValue\",
                            \"Resource\": \"arn:aws:secretsmanager:$region:$account:secret:$prefix/*\"}]
        }"
        log "waiting for the role to propagate"
        sleep 15
    fi
    aws_ iam get-role --role-name "$role" --query Role.Arn --output text
}

# Runs in the fetch container, the audit key is converted by the prover image afterwards.
key_fetch_script() {
    local lock="prover/server/prover/provingkeys/proving-keys.lock" checksum="custom-rings/custom-ring-keys.CHECKSUM"
    local name sha
    printf 'set -eu\ncd /keys\n'
    # shellcheck disable=SC2016
    printf 'fetch() { [ -f "$2" ] && echo "$3  $2" | sha256sum -c -s && return; wget -q -O "$2.part" "$1" && echo "$3  $2.part" | sha256sum -c -s && mv "$2.part" "$2"; }\n'
    for name in auditor_key_encryption_pk.bin auditor_key_encryption_vk.bin; do
        sha="$(awk -v n="$name" '$2 == n { print $1 }' "$checksum")"
        printf 'fetch %s/%s %s %s\n' "$keys_release" "$name" "$name" "$sha"
    done
    for name in transfer_ring_1_2.key transfer_ring_2_2.key; do
        sha="$(jq -r --arg n "$name" '.keys[$n].sha256' "$lock")"
        printf 'fetch %s/%s %s %s\n' "$published_keys" "$name" "$name" "$sha"
    done
}

ensure_load_balancer() {
    local vpc="$1" subnets="$2" arn
    arn="$(aws_ elbv2 describe-load-balancers --names "$load_balancer" --query 'LoadBalancers[0].LoadBalancerArn' --output text 2>/dev/null || true)"
    if [[ "$arn" == None || -z "$arn" ]]; then
        local subnet_list
        IFS=, read -r -a subnet_list <<< "$subnets"
        arn="$(aws_ elbv2 create-load-balancer --name "$load_balancer" --type network --scheme internet-facing \
            --subnets "${subnet_list[@]}" --tags "$tag_spec" --query 'LoadBalancers[0].LoadBalancerArn' --output text)"
    fi
    local service port group
    for service in prover ring-rpc; do
        port="$prover_port"; [[ "$service" == prover ]] || port="$ring_rpc_port"
        group="$(aws_ elbv2 describe-target-groups --names "$prefix-$service" --query 'TargetGroups[0].TargetGroupArn' --output text 2>/dev/null || true)"
        if [[ "$group" == None || -z "$group" ]]; then
            group="$(aws_ elbv2 create-target-group --name "$prefix-$service" --protocol TCP --port "$port" --vpc-id "$vpc" \
                --target-type ip --health-check-protocol HTTP --health-check-path /health --tags "$tag_spec" \
                --query 'TargetGroups[0].TargetGroupArn' --output text)"
        fi
        if [[ -z "$(aws_ elbv2 describe-listeners --load-balancer-arn "$arn" --query "Listeners[?Port==\`$port\`].ListenerArn" --output text)" ]]; then
            aws_ elbv2 create-listener --load-balancer-arn "$arn" --protocol TCP --port "$port" \
                --default-actions "Type=forward,TargetGroupArn=$group" --tags "$tag_spec" >/dev/null
        fi
    done
    aws_ elbv2 describe-load-balancers --load-balancer-arns "$arn" --query 'LoadBalancers[0].DNSName' --output text
}

target_group_arn() {
    aws_ elbv2 describe-target-groups --names "$prefix-$1" --query 'TargetGroups[0].TargetGroupArn' --output text
}

# The root secret is created once and never rotated by this script, a rotation
# would change every derived auditor key.
ensure_secret() {
    if ! aws_ secretsmanager describe-secret --secret-id "$secret" >/dev/null 2>&1; then
        aws_ secretsmanager create-secret --name "$secret" --secret-string "$(openssl rand -hex 32)" --tags "$tag_spec" >/dev/null
    fi
    aws_ secretsmanager describe-secret --secret-id "$secret" --query ARN --output text
}

register_prover() {
    local image="$1" role_arn="$2"
    aws_ ecs register-task-definition --family "$prefix-prover" --tags "$ecs_tag_spec" \
        --requires-compatibilities FARGATE --network-mode awsvpc --cpu 4096 --memory 16384 \
        --execution-role-arn "$role_arn" --runtime-platform cpuArchitecture=X86_64,operatingSystemFamily=LINUX \
        --volumes '[{"name": "keys"}]' \
        --container-definitions "$(jq -n --arg image "$image" --arg redis "$redis_image" --arg fetch "$fetch_image" \
            --arg script "$(key_fetch_script)" --arg group "$log_group" --arg region "$region" --argjson port "$prover_port" '
            def logs(p): {logDriver: "awslogs", options: {"awslogs-group": $group, "awslogs-region": $region, "awslogs-stream-prefix": p}};
            def keys: [{sourceVolume: "keys", containerPath: "/keys"}];
            [
            {name: "redis", image: $redis, essential: true, logConfiguration: logs("redis")},
            {name: "fetch", image: $fetch, essential: false, user: "0", mountPoints: keys,
             command: ["sh", "-c", ($script + "\nchown -R 65532:65532 /keys")], logConfiguration: logs("fetch")},
            {name: "convert", image: $image, essential: false, mountPoints: keys,
             dependsOn: [{containerName: "fetch", condition: "SUCCESS"}],
             command: ["convert-auditor-key-encryption", "--pk", "/keys/auditor_key_encryption_pk.bin",
                       "--vk", "/keys/auditor_key_encryption_vk.bin", "--output", "/keys/custom_ring_audit_transfer.key"],
             logConfiguration: logs("convert")},
            {name: "prover", image: $image, essential: true, mountPoints: keys,
             dependsOn: [{containerName: "redis", condition: "START"}, {containerName: "convert", condition: "SUCCESS"}],
             command: ["start", "--keys-dir", "/keys/", "--prover-address", ("0.0.0.0:" + ($port|tostring)),
                       "--auto-download=true", "--redis-url", "redis://127.0.0.1:6379/0"],
             portMappings: [{containerPort: $port, protocol: "tcp"}],
             logConfiguration: logs("prover")}
        ]')" --query 'taskDefinition.taskDefinitionArn' --output text
}

register_ring_rpc() {
    local image="$1" role_arn="$2" secret_arn="$3" indexer="$4" rpc="$5"
    aws_ ecs register-task-definition --family "$prefix-ring-rpc" --tags "$ecs_tag_spec" \
        --requires-compatibilities FARGATE --network-mode awsvpc --cpu 512 --memory 1024 \
        --execution-role-arn "$role_arn" --runtime-platform cpuArchitecture=X86_64,operatingSystemFamily=LINUX \
        --container-definitions "$(jq -n --arg image "$image" --arg secret "$secret_arn" \
            --arg indexer "$indexer" --arg rpc "$rpc" --arg origins "${RINGS_TEST_ORIGINS:-http://localhost:3000}" \
            --arg rp "${RINGS_TEST_RP_ID:-localhost}" --arg group "$log_group" --arg region "$region" --argjson port "$ring_rpc_port" '[
            {name: "ring-rpc", image: $image, essential: true,
             entryPoint: ["/bin/sh", "-c"],
             command: ["umask 077 && printf %s \"$ROOT_SECRET\" > /var/lib/ring-rpc/root.key && exec ring-rpc serve"],
             secrets: [{name: "ROOT_SECRET", valueFrom: $secret}],
             environment: [
               {name: "RING_RPC_BIND", value: "0.0.0.0"}, {name: "RING_RPC_INSECURE_PUBLIC_BIND", value: "true"},
               {name: "RING_RPC_PORT", value: ($port|tostring)},
               {name: "RING_RPC_INDEXER_URL", value: $indexer}, {name: "RING_RPC_SOLANA_RPC_URL", value: $rpc},
               {name: "RING_RPC_ROOT_SECRET_FILE", value: "/var/lib/ring-rpc/root.key"},
               {name: "RING_RPC_ALLOW_ORIGINS", value: $origins}, {name: "RING_RPC_WEBAUTHN_RP_ID", value: $rp}],
             portMappings: [{containerPort: $port, protocol: "tcp"}],
             logConfiguration: {logDriver: "awslogs", options: {"awslogs-group": $group, "awslogs-region": $region, "awslogs-stream-prefix": "ring-rpc"}}}
        ]')" --query 'taskDefinition.taskDefinitionArn' --output text
}

ensure_service() {
    local name="$1" task_definition="$2" subnets="$3" sg="$4" container="$5" port="$6"
    local status
    status="$(aws_ ecs describe-services --cluster "$cluster" --services "$name" --query 'services[0].status' --output text 2>/dev/null || true)"
    if [[ "$status" == ACTIVE ]]; then
        aws_ ecs update-service --cluster "$cluster" --service "$name" --task-definition "$task_definition" --force-new-deployment >/dev/null
    else
        aws_ ecs create-service --cluster "$cluster" --service-name "$name" --task-definition "$task_definition" \
            --desired-count 1 --launch-type FARGATE --tags "$ecs_tag_spec" --health-check-grace-period-seconds 120 \
            --load-balancers "targetGroupArn=$(target_group_arn "$container"),containerName=$container,containerPort=$port" \
            --network-configuration "awsvpcConfiguration={subnets=[$subnets],securityGroups=[$sg],assignPublicIp=ENABLED}" >/dev/null
    fi
}

public_ip() {
    local task
    task="$(aws_ ecs list-tasks --cluster "$cluster" --service-name "$1" --desired-status RUNNING --query 'taskArns[0]' --output text 2>/dev/null || true)"
    [[ "$task" != None && -n "$task" ]] || { echo "-"; return; }
    local eni
    eni="$(aws_ ecs describe-tasks --cluster "$cluster" --tasks "$task" \
        --query "tasks[0].attachments[0].details[?name=='networkInterfaceId'].value" --output text)"
    aws_ ec2 describe-network-interfaces --network-interface-ids "$eni" --query 'NetworkInterfaces[0].Association.PublicIp' --output text
}

up() {
    [[ $# -eq 0 ]] || usage
    local indexer="${RINGS_TEST_INDEXER_URL:?set RINGS_TEST_INDEXER_URL to the photon the ring RPC reads}"
    local rpc="${RINGS_TEST_SOLANA_RPC_URL:-https://api.devnet.solana.com}"
    local prover_tag="${RINGS_TEST_PROVER_TAG:-prover-$branch-${sha:0:12}}"
    local ring_rpc_tag="${RINGS_TEST_RING_RPC_TAG:-ring-rpc-$branch-${sha:0:12}}"

    log "== images"
    ensure_repository zolana-ring-rpc
    local service tag repository
    for service in prover ring-rpc; do
        tag="$prover_tag"; repository=zolana-prover
        [[ "$service" == prover ]] || { tag="$ring_rpc_tag"; repository=zolana-ring-rpc; }
        if ! aws_ ecr describe-images --repository-name "$repository" --image-ids "imageTag=$tag" >/dev/null 2>&1; then
            tools/publish-image.sh "$service" --repository "$repository" --tag "$tag" --push >&2
        fi
    done

    log "== network, load balancer, role, logs, cluster, secret"
    read -r vpc subnets <<< "$(vpc_and_subnets)"
    local sg role_arn secret_arn
    sg="$(ensure_security_group "$vpc")"
    ensure_load_balancer "$vpc" "$subnets" >/dev/null
    role_arn="$(ensure_role)"
    aws_ logs describe-log-groups --log-group-name-prefix "$log_group" --query "logGroups[?logGroupName=='$log_group']" --output text | grep -q . \
        || aws_ logs create-log-group --log-group-name "$log_group" --tags "$prefix=1"
    aws_ ecs describe-clusters --clusters "$cluster" --query "clusters[?status=='ACTIVE']" --output text | grep -q . \
        || aws_ ecs create-cluster --cluster-name "$cluster" --tags "$ecs_tag_spec" >/dev/null
    secret_arn="$(ensure_secret)"

    log "== services"
    local prover_td ring_rpc_td
    prover_td="$(register_prover "$registry/zolana-prover:$prover_tag" "$role_arn")"
    ring_rpc_td="$(register_ring_rpc "$registry/zolana-ring-rpc:$ring_rpc_tag" "$role_arn" "$secret_arn" "$indexer" "$rpc")"
    ensure_service "$prefix-prover" "$prover_td" "$subnets" "$sg" prover "$prover_port"
    ensure_service "$prefix-ring-rpc" "$ring_rpc_td" "$subnets" "$sg" ring-rpc "$ring_rpc_port"
    log "waiting for the services to stabilize"
    aws_ ecs wait services-stable --cluster "$cluster" --services "$prefix-prover" "$prefix-ring-rpc"
    status
}

status() {
    local dns
    dns="$(aws_ elbv2 describe-load-balancers --names "$load_balancer" --query 'LoadBalancers[0].DNSName' --output text 2>/dev/null || echo "-")"
    echo "prover    http://$dns:$prover_port   (task $(public_ip "$prefix-prover"))"
    echo "ring rpc  http://$dns:$ring_rpc_port   (task $(public_ip "$prefix-ring-rpc"))"
    curl -sf --max-time 10 "http://$dns:$prover_port/health" && echo || echo "prover health not reachable yet"
    curl -sf --max-time 10 "http://$dns:$ring_rpc_port/health" && echo || echo "ring rpc health not reachable yet"
    echo "logs      aws logs tail $log_group --region $region --follow"
}

down() {
    local name
    for name in "$prefix-prover" "$prefix-ring-rpc"; do
        if [[ "$(aws_ ecs describe-services --cluster "$cluster" --services "$name" --query 'services[0].status' --output text 2>/dev/null)" == ACTIVE ]]; then
            aws_ ecs delete-service --cluster "$cluster" --service "$name" --force >/dev/null
        fi
    done
    aws_ ecs wait services-inactive --cluster "$cluster" --services "$prefix-prover" "$prefix-ring-rpc" 2>/dev/null || true
    local td
    for td in $(aws_ ecs list-task-definitions --family-prefix "$prefix-" --query 'taskDefinitionArns[]' --output text); do
        aws_ ecs deregister-task-definition --task-definition "$td" >/dev/null
    done
    aws_ ecs delete-cluster --cluster "$cluster" >/dev/null 2>&1 || true
    local lb
    lb="$(aws_ elbv2 describe-load-balancers --names "$load_balancer" --query 'LoadBalancers[0].LoadBalancerArn' --output text 2>/dev/null || true)"
    if [[ "$lb" != None && -n "$lb" ]]; then
        aws_ elbv2 delete-load-balancer --load-balancer-arn "$lb"
        aws_ elbv2 wait load-balancers-deleted --load-balancer-arns "$lb"
    fi
    local group
    for group in $(aws_ elbv2 describe-target-groups --names "$prefix-prover" "$prefix-ring-rpc" --query 'TargetGroups[].TargetGroupArn' --output text 2>/dev/null); do
        aws_ elbv2 delete-target-group --target-group-arn "$group"
    done
    local sg
    sg="$(aws_ ec2 describe-security-groups --filters "Name=group-name,Values=$security_group" --query 'SecurityGroups[0].GroupId' --output text)"
    [[ "$sg" == None || -z "$sg" ]] || { sleep 20; aws_ ec2 delete-security-group --group-id "$sg"; }
    aws_ logs delete-log-group --log-group-name "$log_group" 2>/dev/null || true
    aws_ secretsmanager delete-secret --secret-id "$secret" --force-delete-without-recovery >/dev/null 2>&1 || true
    if aws_ iam get-role --role-name "$role" >/dev/null 2>&1; then
        aws_ iam detach-role-policy --role-name "$role" --policy-arn arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy
        aws_ iam delete-role-policy --role-name "$role" --policy-name secrets
        aws_ iam delete-role --role-name "$role"
    fi
    echo "removed every $prefix-* resource"
}

case "$command" in
    up) up "$@" ;;
    status) status ;;
    down) down ;;
    *) usage ;;
esac
