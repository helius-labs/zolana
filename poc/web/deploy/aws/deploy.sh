#!/usr/bin/env bash
# Deploy an already built and tested release. AWS_PROFILE is honored by the CLI.
set -euo pipefail
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/../../../.." && pwd)"
release="${1:?usage: deploy.sh RELEASE_ID [DIST_DIRECTORY]}"
dist="${2:-$repo_root/poc/web/dist}"
stack="${ZOLANA_DEMO_STACK:-zolana-mopro-arkworks-demo}"
region="${AWS_REGION:-eu-north-1}"
[[ "$release" =~ ^[a-zA-Z0-9][a-zA-Z0-9-]{0,100}$ ]] || { echo 'Invalid release ID' >&2; exit 1; }
for file in index.html build-info.json prover/zolana-prover.wasm prover/accelerator/gnark_kernel_bg.wasm keys/manifest.json fixtures/transfer-2x3.json; do
  [[ -f "$dist/$file" ]] || { echo "Missing release file: $file" >&2; exit 1; }
done
# Root HTML must refer to this immutable release, including runtime asset URLs.
node --input-type=module - "$dist" "$release" <<'JS'
import { readFileSync } from 'node:fs';
const [dist, release] = process.argv.slice(2);
const html = readFileSync(`${dist}/index.html`, 'utf8');
const info = JSON.parse(readFileSync(`${dist}/build-info.json`, 'utf8'));
if (!html.includes(`/releases/${release}/assets/`) || info.release !== release) {
  throw new Error('Build the app with --base /releases/RELEASE_ID/ and matching build-info.json');
}
JS
aws_() { aws --region "$region" "$@"; }
aws_ cloudformation deploy --stack-name "$stack" --template-file "$script_dir/template.yaml" \
  --tags Project=zolana Component=mopro-browser-demo --no-fail-on-empty-changeset
outputs="$(aws_ cloudformation describe-stacks --stack-name "$stack" --query 'Stacks[0].Outputs' --output json)"
output() { node -e 'const items=JSON.parse(process.argv[1]); console.log(items.find(x=>x.OutputKey===process.argv[2]).OutputValue)' "$outputs" "$1"; }
bucket="$(output BucketName)"
distribution="$(output DistributionId)"
url="$(output DemoUrl)"
# Never replace release assets: open tabs keep using their matching Go/Rust pair.
existing="$(aws_ s3api list-objects-v2 --bucket "$bucket" --prefix "releases/$release/" --max-keys 1 --query KeyCount --output text)"
[[ "$existing" == 0 ]] || { echo "Release $release already exists; use a new release ID" >&2; exit 1; }
aws_ s3 sync "$dist/" "s3://$bucket/releases/$release/" \
  --cache-control 'public,max-age=31536000,immutable' --only-show-errors
# Explicit MIME type is needed by WebAssembly.instantiateStreaming.
while IFS= read -r -d '' wasm; do
  relative="${wasm#"$dist/"}"
  aws_ s3 cp "$wasm" "s3://$bucket/releases/$release/$relative" \
    --content-type application/wasm --cache-control 'public,max-age=31536000,immutable' --only-show-errors
done < <(find "$dist" -type f -name '*.wasm' -print0)
# Publish the entry point last, after every referenced asset is available.
aws_ s3 cp "$dist/index.html" "s3://$bucket/index.html" \
  --content-type text/html --cache-control 'no-cache,max-age=0,must-revalidate' --only-show-errors
aws_ cloudfront create-invalidation --distribution-id "$distribution" --paths '/' '/index.html' --output json
printf 'Demo: %s/\nRelease: %s/releases/%s/\nBucket: %s\nDistribution: %s\n' "$url" "$url" "$release" "$bucket" "$distribution"
