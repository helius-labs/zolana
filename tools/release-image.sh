#!/usr/bin/env bash
# Resume immutable publication using a signed config digest recorded before push.
set -euo pipefail
mode=$1 service=$2 repository=$3 tag=$4 signer=$5
registry=558215002830.dkr.ecr.eu-north-1.amazonaws.com
bucket=zolana-nitro-eif-558215002830
image="$registry/$repository:$tag"
intent="$RUNNER_TEMP/build-intent.json"
verify() {
  local args=(--source-digest "$GITHUB_SHA")
  if [[ "${STABLE_ARTIFACT:-}" == true ]]; then args=(--source-ref refs/heads/main); fi
  gh attestation verify "$1" --repo "$GITHUB_REPOSITORY" --signer-workflow "$GITHUB_REPOSITORY/.github/workflows/$signer" "${args[@]}" --deny-self-hosted-runners
}
remote_digest() {
  aws ecr describe-images --repository-name "$repository" --image-ids "imageTag=$1" --query 'imageDetails[0].imageDigest' --output text
}
case "$mode" in
  resolve)
    tags=("$tag")
    [[ -z "${COMMIT_ALIAS:-}" ]] || tags+=("$COMMIT_ALIAS")
    for candidate_tag in "${tags[@]}"; do
      if result="$(remote_digest "$candidate_tag" 2>&1)"; then
        digest=$result
        pin="$registry/$repository@$digest"
        docker pull "$pin"
        if ! verify "oci://$pin"; then
          config="$(docker inspect --format '{{.Id}}' "$pin")"
          publisher="$(docker inspect --format '{{index .Config.Labels "org.zolana.publisher.revision"}}' "$pin")"
          [[ "${STABLE_ARTIFACT:-}" == true ]] || publisher=$GITHUB_SHA
          [[ "$publisher" =~ ^[0-9a-f]{40}$ ]]
          aws s3 cp "s3://$bucket/publication/$service/$publisher/${config#sha256:}.json" "$intent"
          verify "$intent"
          jq -e --arg config "$config" --arg commit "$publisher" --arg service "$service" \
            '.config_digest == $config and .source_commit == $commit and .service == $service' "$intent" > /dev/null
          echo 'needs_attestation=true' >> "$GITHUB_OUTPUT"
        fi
        docker tag "$pin" "$image"
        echo "digest=$digest" >> "$GITHUB_OUTPUT"
        break
      elif [[ "$result" != *ImageNotFoundException* ]]; then
        echo "$result" >&2
        exit 1
      fi
    done
    ;;
  intent)
    config="$(docker inspect --format '{{.Id}}' "$image")"
    jq -n --arg config "$config" --arg commit "$GITHUB_SHA" --arg service "$service" \
      '{config_digest:$config,source_commit:$commit,service:$service}' > "$intent"
    ;;
  retain-intent)
    config="$(jq -r .config_digest "$intent")"
    key="publication/$service/$GITHUB_SHA/${config#sha256:}.json"
    if ! result="$(aws s3api put-object --bucket "$bucket" --key "$key" --body "$intent" --content-type application/json --if-none-match '*' 2>&1)"; then
      [[ "$result" == *PreconditionFailed* ]] || { echo "$result" >&2; exit 1; }
      aws s3api get-object --bucket "$bucket" --key "$key" "$RUNNER_TEMP/previous-intent.json" > /dev/null
      cmp -s "$intent" "$RUNNER_TEMP/previous-intent.json"
    fi
    ;;
  push)
    digest="${EXISTING_DIGEST:-}"
    if [[ -z "$digest" ]]; then
      destination="$tag"
      [[ -z "${COMMIT_ALIAS:-}" ]] || destination="$COMMIT_ALIAS"
      docker tag "$image" "$registry/$repository:$destination"
      docker push "$registry/$repository:$destination"
      digest="$(remote_digest "$destination")"
    fi
    manifest="$(aws ecr batch-get-image --repository-name "$repository" --image-ids "imageDigest=$digest" --query 'images[0].imageManifest' --output text)"
    if ! result="$(aws ecr put-image --repository-name "$repository" --image-tag "$tag" --image-manifest "$manifest" 2>&1)"; then
      [[ "$(remote_digest "$tag")" == "$digest" ]] || { echo "$result" >&2; exit 1; }
    fi
    {
      echo "digest=$digest"
      echo "image=$registry/$repository@$digest"
    } >> "$GITHUB_OUTPUT"
    ;;
  *) echo 'Expected resolve, intent, retain-intent or push' >&2; exit 2 ;;
esac
