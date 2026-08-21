#!/usr/bin/env bash
# Stand up an isolated test deployment of the prover and one ring RPC on ECS.
# Every resource is named zolana-rings-test-* and tagged zolana-rings-test=1,
# nothing it creates is shared with another deployment.
#
#   tools/rings-test-deploy.sh up RING_DIR     build, publish, create, start
#   tools/rings-test-deploy.sh status          addresses and health
#   tools/rings-test-deploy.sh down            delete everything it created
#
# RING_DIR is a generated ring (ring.toml, keys/auditor.key). The ring RPC serves
# that ring against the indexer and Solana RPC of its [devnet] section. Both
# services sit behind one network load balancer, its DNS name is stable across
# task replacements.
#
# Needs aws (with write access), docker, jq, just, go, python3.
#
# Environment
#   AWS_REGION            default eu-north-1
#   RINGS_TEST_VPC        VPC id, default the account's default VPC
#   RINGS_TEST_ORIGINS    browser origins for the ring RPC, default http://localhost:3000
#   RINGS_TEST_RP_ID      WebAuthn relying party id, default localhost
set -euo pipefail

usage() {
    sed -n '2,23p' "$0" | sed 's/^# \{0,1\}//' >&2
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
account="$(aws sts get-caller-identity --query Account --output text)"
registry="$account.dkr.ecr.$region.amazonaws.com"
sha="$(git rev-parse HEAD)"
cluster="$prefix"
role="$prefix-exec"
log_group="/$prefix"
bucket="$prefix-keys-$account"
secret="$prefix/auditor-key"
security_group="$prefix-sg"
load_balancer="$prefix"
prover_port=3001
ring_rpc_port=8785
redis_image="public.ecr.aws/docker/library/redis:7.4.4-alpine3.21"

aws_() { aws --region "$region" "$@"; }

log() { printf '%s\n' "$*" >&2; }

# ring.toml only uses `key = "value"` lines under [section] headers.
toml_value() {
    python3 - "$1" "$2" "$3" <<'EOF'
import re, sys
path, section, key = sys.argv[1:]
if not key:
    section, key = "", section
current = ""
for line in open(path):
    line = line.split("#", 1)[0].strip()
    header = re.fullmatch(r"\[(.+)\]", line)
    if header:
        current = header.group(1)
        continue
    pair = re.fullmatch(r'([A-Za-z0-9_]+)\s*=\s*"(.*)"', line)
    if pair and current == section and pair.group(1) == key:
        print(pair.group(2))
        break
else:
    sys.exit(f"{key} not found in [{section}] of {path}")
EOF
}

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

ensure_keys_bucket() {
    local lock_prefix
    lock_prefix="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["prefix"])' prover/server/prover/provingkeys/proving-keys.lock)"
    if ! aws_ s3api head-bucket --bucket "$bucket" >/dev/null 2>&1; then
        aws_ s3api create-bucket --bucket "$bucket" --create-bucket-configuration "LocationConstraint=$region" >/dev/null
        aws_ s3api put-bucket-tagging --bucket "$bucket" --tagging "TagSet=[{$tag_spec}]"
        aws_ s3api put-public-access-block --bucket "$bucket" \
            --public-access-block-configuration BlockPublicAcls=false,IgnorePublicAcls=false,BlockPublicPolicy=false,RestrictPublicBuckets=false
        # Proving keys are public setup parameters, the prover pins their sha256 from its embedded lockfile.
        aws_ s3api put-bucket-policy --bucket "$bucket" --policy "{
            \"Version\": \"2012-10-17\",
            \"Statement\": [{\"Effect\": \"Allow\", \"Principal\": \"*\", \"Action\": \"s3:GetObject\",
                            \"Resource\": \"arn:aws:s3:::$bucket/proving-keys/*\"}]
        }"
    fi
    just ensure-custom-ring-live-keys >&2
    local name
    for name in $(python3 -c 'import json,sys; print(" ".join(json.load(open(sys.argv[1]))["keys"]))' prover/server/prover/provingkeys/proving-keys.lock); do
        [[ -f "prover/server/proving-keys/$name" ]] || continue
        aws_ s3 cp --only-show-errors "prover/server/proving-keys/$name" "s3://$bucket/$lock_prefix/$name"
    done
    echo "https://$bucket.s3.$region.amazonaws.com"
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

ensure_secret() {
    local key_file="$1"
    if aws_ secretsmanager describe-secret --secret-id "$secret" >/dev/null 2>&1; then
        aws_ secretsmanager put-secret-value --secret-id "$secret" --secret-string "$(cat "$key_file")" >/dev/null
    else
        aws_ secretsmanager create-secret --name "$secret" --secret-string "$(cat "$key_file")" --tags "$tag_spec" >/dev/null
    fi
    aws_ secretsmanager describe-secret --secret-id "$secret" --query ARN --output text
}

register_prover() {
    local image="$1" keys_url="$2" role_arn="$3"
    aws_ ecs register-task-definition --family "$prefix-prover" --tags "$tag_spec" \
        --requires-compatibilities FARGATE --network-mode awsvpc --cpu 4096 --memory 16384 \
        --execution-role-arn "$role_arn" --runtime-platform cpuArchitecture=X86_64,operatingSystemFamily=LINUX \
        --container-definitions "$(jq -n --arg image "$image" --arg redis "$redis_image" --arg keys "$keys_url" \
            --arg group "$log_group" --arg region "$region" --argjson port "$prover_port" '[
            {name: "redis", image: $redis, essential: true,
             logConfiguration: {logDriver: "awslogs", options: {"awslogs-group": $group, "awslogs-region": $region, "awslogs-stream-prefix": "redis"}}},
            {name: "prover", image: $image, essential: true, dependsOn: [{containerName: "redis", condition: "START"}],
             command: ["start", "--keys-dir", "/proving-keys/", "--prover-address", ("0.0.0.0:" + ($port|tostring)),
                       "--auto-download=true", "--redis-url", "redis://127.0.0.1:6379/0"],
             environment: [{name: "ZOLANA_PROVING_KEYS_URL", value: $keys}],
             portMappings: [{containerPort: $port, protocol: "tcp"}],
             logConfiguration: {logDriver: "awslogs", options: {"awslogs-group": $group, "awslogs-region": $region, "awslogs-stream-prefix": "prover"}}}
        ]')" --query 'taskDefinition.taskDefinitionArn' --output text
}

register_ring_rpc() {
    local image="$1" role_arn="$2" secret_arn="$3" ring="$4" indexer="$5" rpc="$6"
    aws_ ecs register-task-definition --family "$prefix-ring-rpc" --tags "$tag_spec" \
        --requires-compatibilities FARGATE --network-mode awsvpc --cpu 512 --memory 1024 \
        --execution-role-arn "$role_arn" --runtime-platform cpuArchitecture=X86_64,operatingSystemFamily=LINUX \
        --container-definitions "$(jq -n --arg image "$image" --arg secret "$secret_arn" --arg ring "$ring" \
            --arg indexer "$indexer" --arg rpc "$rpc" --arg origins "${RINGS_TEST_ORIGINS:-http://localhost:3000}" \
            --arg rp "${RINGS_TEST_RP_ID:-localhost}" --arg group "$log_group" --arg region "$region" --argjson port "$ring_rpc_port" '[
            {name: "ring-rpc", image: $image, essential: true,
             entryPoint: ["/bin/sh", "-c"],
             command: ["umask 077 && printf %s \"$AUDITOR_KEY\" > /var/lib/ring-rpc/auditor.key && exec ring-rpc serve"],
             secrets: [{name: "AUDITOR_KEY", valueFrom: $secret}],
             environment: [
               {name: "RING_RPC_BIND", value: "0.0.0.0"}, {name: "RING_RPC_PORT", value: ($port|tostring)},
               {name: "RING_RPC_INDEXER_URL", value: $indexer}, {name: "RING_RPC_SOLANA_RPC_URL", value: $rpc},
               {name: "RING_RPC_RING_PROGRAM_ID", value: $ring}, {name: "RING_RPC_AUDITOR_KEY_FILE", value: "/var/lib/ring-rpc/auditor.key"},
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
            --desired-count 1 --launch-type FARGATE --tags "$tag_spec" --health-check-grace-period-seconds 120 \
            --load-balancers "targetGroupArn=$(target_group_arn "$container"),containerName=$container,containerPort=$port" \
            --network-configuration "awsvpcConfiguration={subnets=[$subnets],securityGroups=[$sg],assignPublicIp=ENABLED}" >/dev/null
    fi
}

public_ip() {
    local task
    task="$(aws_ ecs list-tasks --cluster "$cluster" --service-name "$1" --desired-status RUNNING --query 'taskArns[0]' --output text)"
    [[ "$task" != None && -n "$task" ]] || { echo "-"; return; }
    local eni
    eni="$(aws_ ecs describe-tasks --cluster "$cluster" --tasks "$task" \
        --query "tasks[0].attachments[0].details[?name=='networkInterfaceId'].value" --output text)"
    aws_ ec2 describe-network-interfaces --network-interface-ids "$eni" --query 'NetworkInterfaces[0].Association.PublicIp' --output text
}

up() {
    [[ $# -eq 1 ]] || usage
    local ring_dir="$1"
    local ring_toml="$ring_dir/ring.toml" key_file="$ring_dir/keys/auditor.key"
    [[ -f "$ring_toml" && -f "$key_file" ]] || { log "$ring_dir is not a generated ring with keys/auditor.key"; exit 1; }
    local ring indexer rpc
    ring="$(toml_value "$ring_toml" program_id "")"
    indexer="$(toml_value "$ring_toml" devnet indexer)"
    rpc="$(toml_value "$ring_toml" devnet rpc)"
    [[ -z "$(git status --porcelain --untracked-files=no)" ]] || { log "working tree is dirty"; exit 1; }

    log "== images"
    ensure_repository "$prefix-prover"
    ensure_repository "$prefix-ring-rpc"
    local image_tag="${sha:0:12}"
    tools/publish-image.sh prover --repository "$prefix-prover" --tag "prover-$image_tag" --push >&2 \
        || [[ "$(aws_ ecr describe-images --repository-name "$prefix-prover" --image-ids "imageTag=prover-$image_tag" --query 'length(imageDetails)' --output text)" == 1 ]]
    tools/publish-image.sh ring-rpc --repository "$prefix-ring-rpc" --tag "ring-rpc-$image_tag" --push >&2 \
        || [[ "$(aws_ ecr describe-images --repository-name "$prefix-ring-rpc" --image-ids "imageTag=ring-rpc-$image_tag" --query 'length(imageDetails)' --output text)" == 1 ]]

    log "== proving keys"
    local keys_url
    keys_url="$(ensure_keys_bucket)"

    log "== network, load balancer, role, logs, cluster, secret"
    read -r vpc subnets <<< "$(vpc_and_subnets)"
    local sg role_arn secret_arn
    sg="$(ensure_security_group "$vpc")"
    ensure_load_balancer "$vpc" "$subnets" >/dev/null
    role_arn="$(ensure_role)"
    aws_ logs describe-log-groups --log-group-name-prefix "$log_group" --query "logGroups[?logGroupName=='$log_group']" --output text | grep -q . \
        || aws_ logs create-log-group --log-group-name "$log_group" --tags "$prefix=1"
    aws_ ecs describe-clusters --clusters "$cluster" --query "clusters[?status=='ACTIVE']" --output text | grep -q . \
        || aws_ ecs create-cluster --cluster-name "$cluster" --tags "$tag_spec" >/dev/null
    secret_arn="$(ensure_secret "$key_file")"

    log "== services"
    local prover_td ring_rpc_td
    prover_td="$(register_prover "$registry/$prefix-prover:prover-$image_tag" "$keys_url" "$role_arn")"
    ring_rpc_td="$(register_ring_rpc "$registry/$prefix-ring-rpc:ring-rpc-$image_tag" "$role_arn" "$secret_arn" "$ring" "$indexer" "$rpc")"
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
    for name in "$prefix-prover" "$prefix-ring-rpc"; do
        aws_ ecr delete-repository --repository-name "$name" --force >/dev/null 2>&1 || true
    done
    if aws_ s3api head-bucket --bucket "$bucket" >/dev/null 2>&1; then
        aws_ s3 rm --only-show-errors --recursive "s3://$bucket"
        aws_ s3api delete-bucket --bucket "$bucket"
    fi
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
