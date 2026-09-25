#!/usr/bin/env bash
set -euo pipefail
if [[ $# != 1 || $1 == --help ]]; then
    echo "Usage: $0 OUTPUT_DIRECTORY"
    exit 0
fi
[[ $(uname -s) == Linux && $(uname -m) == x86_64 ]]
root=$(cd "$(dirname "$0")/../.." && pwd)
[[ -z $(git -C "$root" status --porcelain --untracked-files=normal) ]]
mkdir -p "$1"
output=$(cd "$1" && pwd)
scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT
"$root/tools/gpu/fetch-aeglos.sh" "$scratch"
if [[ -z ${CUDA_ARCH:-} ]]; then
    capability=$(nvidia-smi --query-gpu=compute_cap --format=csv,noheader | head -n 1)
    CUDA_ARCH="sm_${capability//./}"
fi
"$root/prover/server/build-aeglos.sh" "$scratch" "$CUDA_ARCH" "$output/light-prover"
(cd "$root" && cargo build --locked --release -p photon-indexer --bin photon --bin photon-migration)
target_dir=${CARGO_TARGET_DIR:-$root/target}
[[ $target_dir == /* ]] || target_dir="$root/$target_dir"
cp "$target_dir/release/"{photon,photon-migration} "$output/"
cp "$root/prover/server/prover/backend/aeglos-source.lock" "$root/LICENSE" "$root/THIRD_PARTY_NOTICES" "$output/"
cp "$root/tools/gpu/"{install.sh,run-service.sh,supervisord.conf,validate.py} "$output/"
git -C "$root" rev-parse HEAD > "$output/source-revision"
printf '%s\n' "$CUDA_ARCH" > "$output/cuda-arch"
(cd "$output" && sha256sum light-prover photon photon-migration aeglos-source.lock source-revision cuda-arch LICENSE THIRD_PARTY_NOTICES install.sh run-service.sh supervisord.conf validate.py > SHA256SUMS)
