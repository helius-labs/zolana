#!/usr/bin/env bash
set -euo pipefail
if [[ $# != 2 ]]; then
    echo "Usage: $0 REPOSITORY TAG" >&2
    exit 1
fi
for _ in {1..10}; do
    if digest=$(aws ecr describe-images --repository-name "$1" --image-ids "imageTag=$2" \
        --query 'imageDetails[0].imageDigest' --output text 2>/dev/null) && [[ $digest == sha256:* ]]; then
        printf '%s\n' "$digest"
        exit 0
    fi
    sleep 2
done
echo "Could not resolve the digest of $1:$2" >&2
exit 1
