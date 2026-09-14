#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
asset_dir="$repo_root/mobile/zolana-mobile/mopro_flutter_bindings/example/assets/proving"
key_name="transfer_confidential_2_3.key"
key="$repo_root/prover/server/proving-keys/$key_name"
assignment="$repo_root/target/assignment-2x3.bin"
request="${ZOLANA_DEMO_PROOF_REQUEST:-$repo_root/mobile/fixtures/prove-request-2x3.json}"
manifest="$repo_root/prover/server/prover/provingkeys/proving-keys.lock"

sha256() {
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{ print $1 }'
  else
    sha256sum "$1" | awk '{ print $1 }'
  fi
}

expected="$(python3 -c 'import json, sys; print(json.load(open(sys.argv[1]))["keys"][sys.argv[2]]["sha256"])' "$manifest" "$key_name")"
if [[ ! -f "$key" ]] || [[ "$(sha256 "$key")" != "$expected" ]]; then
  prefix="$(python3 -c 'import json, sys; print(json.load(open(sys.argv[1]))["prefix"])' "$manifest")"
  base_url="${ZOLANA_PROVING_KEYS_URL:-https://d3gbdb0egjwcw9.cloudfront.net}"
  temporary_key="$(mktemp)"
  trap 'rm -f "$temporary_key"' EXIT
  echo "downloading $key_name"
  curl -fsSL "$base_url/$prefix/$key_name" -o "$temporary_key"
  if [[ "$(sha256 "$temporary_key")" != "$expected" ]]; then
    echo "downloaded proving key checksum does not match the lockfile" >&2
    exit 1
  fi
  mkdir -p "$(dirname "$key")"
  mv "$temporary_key" "$key"
  trap - EXIT
fi

if [[ ! -f "$assignment" ]]; then
  if [[ ! -f "$request" ]]; then
    echo "missing proof request: $request" >&2
    exit 1
  fi
  echo "solving the committed 2→3 proof request with gnark"
  mkdir -p "$(dirname "$assignment")"
  (
    cd "$repo_root/prover/server"
    go run ./cmd/export-solved-assignment \
      --key "$key" \
      --request "$request" \
      --out "$assignment"
  )
fi

mkdir -p "$asset_dir"
cp "$key" "$asset_dir/transfer_confidential_2_3.key"
cp "$assignment" "$asset_dir/assignment-2x3.bin"
echo "staged demo proving assets in $asset_dir"
