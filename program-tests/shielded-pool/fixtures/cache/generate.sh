#!/usr/bin/env bash
set -euo pipefail
root=$(git rev-parse --show-toplevel)
fixtures="$root/program-tests/shielded-pool/fixtures/cache"
cd "$root/prover/server"
# Setup is cache-first; remove only these keys to intentionally rotate them.
go run "$fixtures/setup.go"
(cd proving-keys/cached && shasum -a 256 *.pk *.r1cs *.vk | sort -k2) > "$fixtures/keys.sha256"
for vk in proving-keys/cached/*.vk; do
  name=$(basename "$vk" .vk)
  "$root/target/debug/xtask" bsb22-vk "$vk" "$root/program-libs/interface/src/verifying_keys" "$name.rs"
done
bridge=circuits/spp_transaction/shared/program_cache_generation_test.go
[[ ! -e "$bridge" ]] || { echo "fixture bridge already exists" >&2; exit 1; }
merge_bridge=circuits/spp_merge/program_cache_generation_test.go
[[ ! -e "$merge_bridge" ]] || { echo "merge fixture bridge already exists" >&2; exit 1; }
trap 'rm -f "$bridge" "$merge_bridge"' EXIT
cp "$fixtures/generate_test.go.txt" "$bridge"
CACHE_FIXTURE_DIR="$fixtures" go test ./circuits/spp_transaction/shared -run '^TestGenerateProgramCacheFixtures$' -count=1

cp "$fixtures/generate_merge_test.go.txt" "$merge_bridge"
CACHE_FIXTURE_DIR="$fixtures" go test ./circuits/spp_merge -run '^TestGenerateProgramMergeCacheFixture$' -count=1
