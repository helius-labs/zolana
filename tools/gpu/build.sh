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
read -r _ archive < "$root/prover/server/prover/backend/aeglos-source.lock"
mkdir "$scratch/aeglos"
tar -xf "$scratch/$archive" -C "$scratch/aeglos"
if [[ -z ${CUDA_ARCH:-} ]]; then
    capability=$(nvidia-smi --query-gpu=compute_cap --format=csv,noheader | head -n 1)
    CUDA_ARCH="sm_${capability//./}"
fi
[[ $CUDA_ARCH =~ ^sm_[0-9]+$ ]]
make -C "$scratch/aeglos" -j "${BUILD_JOBS:-4}" ARCH="$CUDA_ARCH" PREFIX="$scratch/native" install
export GOWORK="$scratch/go.work"
(cd "$scratch" && go work init "$root/prover/server" "$scratch/aeglos")
[[ -z $(go env GOFLAGS) ]]
(cd "$root/prover/server" && CGO_ENABLED=1 GOAMD64="${GOAMD64:-v3}" \
    CGO_LDFLAGS="-L$scratch/native/lib -L/usr/local/cuda/lib64" \
    go build -tags aeglos -trimpath -pgo=auto -ldflags='-s -w -buildid=' -o "$output/light-prover" .)
(cd "$root" && cargo build --locked --release -p photon-indexer --bin photon)
target_dir=${CARGO_TARGET_DIR:-$root/target}
[[ $target_dir == /* ]] || target_dir="$root/$target_dir"
cp "$target_dir/release/photon" "$output/photon"
cp "$root/prover/server/prover/backend/aeglos-source.lock" "$root/LICENSE" "$root/THIRD_PARTY_NOTICES" "$output/"
cp "$root/tools/gpu/"{install.sh,run-service.sh,supervisord.conf,validate.py} "$output/"
git -C "$root" rev-parse HEAD > "$output/source-revision"
printf '%s\n' "$CUDA_ARCH" > "$output/cuda-arch"
(cd "$output" && sha256sum light-prover photon aeglos-source.lock source-revision cuda-arch LICENSE THIRD_PARTY_NOTICES install.sh run-service.sh supervisord.conf validate.py > SHA256SUMS)
