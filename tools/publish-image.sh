#!/usr/bin/env bash
# Build one service image locally and publish it to ECR under the same rules as
# .github/workflows/publish-image.yml, then optionally roll an ECS service to it.
#
#   tools/publish-image.sh <photon|prover|forester|ring-rpc> [options]
#
#   --tag TAG            image tag, default <service>-<branch>-<sha12>
#   --push               push to ECR, without it the image is only built and smoke tested
#   --deploy CLUSTER/SVC register a task definition revision on the pushed image
#                        and update the ECS service, implies --push
#   --container NAME     container name inside the task definition, default <service>
#
# Environment
#   ZOLANA_ECR_REGISTRY  default 558215002830.dkr.ecr.eu-north-1.amazonaws.com
#   AWS_REGION           default eu-north-1
#   AWS_PROFILE          honoured by the aws CLI
#
# A tag with the -zolana- release shape is only accepted for a commit on
# origin/main. Tags are never overwritten. The sha-<commit> alias is published
# first and the requested tag points at that exact remote image.
set -euo pipefail

usage() {
    sed -n '2,18p' "$0" | sed 's/^# \{0,1\}//' >&2
    exit 2
}

[[ $# -ge 1 ]] || usage
service="$1"
shift
tag=""
push=0
deploy=""
container=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --tag) tag="$2"; shift 2 ;;
        --push) push=1; shift ;;
        --deploy) deploy="$2"; push=1; shift 2 ;;
        --container) container="$2"; shift 2 ;;
        *) usage ;;
    esac
done

root="$(git rev-parse --show-toplevel)"
cd "$root"
registry="${ZOLANA_ECR_REGISTRY:-558215002830.dkr.ecr.eu-north-1.amazonaws.com}"
region="${AWS_REGION:-eu-north-1}"
sha="$(git rev-parse HEAD)"
branch="$(git rev-parse --abbrev-ref HEAD | tr -c 'A-Za-z0-9._\n' '-')"

case "$service" in
    photon)   repository=zolana-photon;   context=.;             file=services/photon/Dockerfile ;;
    prover)   repository=zolana-prover;   context=prover/server; file=prover/server/Dockerfile.light ;;
    forester) repository=zolana-forester; context=.;             file=forester/Dockerfile ;;
    ring-rpc) repository=zolana-ring-rpc; context=.;             file=services/ring-rpc/Dockerfile ;;
    *) echo "unknown service $service" >&2; exit 2 ;;
esac
[[ -f "$file" ]] || { echo "$file is missing on this commit" >&2; exit 1; }
container="${container:-$service}"

if [[ -z "$tag" ]]; then
    tag="${service}-${branch}-${sha:0:12}"
fi
if [[ "$tag" == *-zolana-* ]]; then
    expected="${service}-zolana-${sha:0:12}"
    [[ "$tag" == "$expected" ]] || { echo "release tag must be $expected" >&2; exit 1; }
    git fetch --no-tags origin +refs/heads/main:refs/remotes/origin/main
    git merge-base --is-ancestor "$sha" origin/main || { echo "a release must be built from a commit on origin/main" >&2; exit 1; }
fi
if [[ -n "$(git status --porcelain --untracked-files=no)" ]]; then
    echo "working tree is dirty, the image would not match $sha" >&2
    exit 1
fi

image="$registry/$repository"
sha_image="$image:sha-$sha"
tag_image="$image:$tag"

docker buildx build \
    --platform linux/amd64 \
    --file "$file" \
    --tag "$sha_image" \
    --tag "$tag_image" \
    --label "org.opencontainers.image.revision=$sha" \
    --label "org.opencontainers.image.source=https://github.com/helius-labs/zolana" \
    --load \
    "$context"

case "$service" in
    photon)
        docker run --rm --entrypoint photon "$tag_image" --version
        test "$(docker run --rm --entrypoint id "$tag_image" -u)" = 10001
        ;;
    prover)   docker run --rm "$tag_image" --help >/dev/null ;;
    forester) docker run --rm "$tag_image" --version ;;
    ring-rpc)
        docker run --rm "$tag_image" --help >/dev/null
        test "$(docker run --rm --entrypoint id "$tag_image" -u)" = 10002
        ;;
esac
echo "built $tag_image"

[[ $push -eq 1 ]] || exit 0

aws ecr get-login-password --region "$region" | docker login --username AWS --password-stdin "$registry"

tag_exists() {
    aws ecr describe-images --region "$region" --repository-name "$repository" \
        --image-ids "imageTag=$1" --query 'imageDetails[0].imageDigest' --output text 2>/dev/null
}
if [[ -n "$(tag_exists "$tag")" ]]; then
    echo "refusing to overwrite published tag $tag" >&2
    exit 1
fi
if [[ -n "$(tag_exists "sha-$sha")" ]]; then
    echo "reusing published sha-$sha"
    docker pull "$sha_image"
else
    docker push "$sha_image"
fi
manifest="$(aws ecr batch-get-image --region "$region" --repository-name "$repository" \
    --image-ids "imageTag=sha-$sha" --query 'images[0].imageManifest' --output text)"
aws ecr put-image --region "$region" --repository-name "$repository" \
    --image-tag "$tag" --image-manifest "$manifest" >/dev/null
digest="$(tag_exists "$tag")"
echo "published $tag_image@$digest"

[[ -n "$deploy" ]] || exit 0

cluster="${deploy%%/*}"
ecs_service="${deploy#*/}"
[[ "$cluster" != "$deploy" && -n "$ecs_service" ]] || { echo "--deploy takes CLUSTER/SERVICE" >&2; exit 1; }
current="$(aws ecs describe-services --region "$region" --cluster "$cluster" --services "$ecs_service" \
    --query 'services[0].taskDefinition' --output text)"
[[ "$current" != None ]] || { echo "service $deploy not found in $cluster" >&2; exit 1; }
definition="$(aws ecs describe-task-definition --region "$region" --task-definition "$current" \
    --query 'taskDefinition' --output json)"
new_definition="$(jq --arg name "$container" --arg image "$image@$digest" '
    if ([.containerDefinitions[] | select(.name == $name)] | length) != 1
    then error("container \($name) not found in task definition") else . end
    | .containerDefinitions |= map(if .name == $name then .image = $image else . end)
    | del(.taskDefinitionArn, .revision, .status, .requiresAttributes, .compatibilities,
          .registeredAt, .registeredBy, .deregisteredAt)' <<< "$definition")"
revision="$(aws ecs register-task-definition --region "$region" --cli-input-json "$new_definition" \
    --query 'taskDefinition.taskDefinitionArn' --output text)"
aws ecs update-service --region "$region" --cluster "$cluster" --service "$ecs_service" \
    --task-definition "$revision" >/dev/null
echo "rolling $deploy to $revision"
aws ecs wait services-stable --region "$region" --cluster "$cluster" --services "$ecs_service"
echo "stable"
