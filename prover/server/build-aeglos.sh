#!/usr/bin/env bash
set -euo pipefail
if [[ $# != 3 ]]; then
    echo "Usage: $0 AEGLOS_ARCHIVE_DIRECTORY CUDA_ARCH OUTPUT" >&2
    exit 1
fi
if [[ ! $2 =~ ^sm_[0-9]+$ ]]; then
    echo 'CUDA_ARCH must name a GPU architecture such as sm_89' >&2
    exit 1
fi
prover=$(cd "$(dirname "$0")" && pwd)
# shellcheck source=/dev/null
source "$prover/release-build.env"
lock="$prover/prover/backend/aeglos-source.lock"
scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT
(cd "$1" && sha256sum -c "$lock")
read -r _ archive < "$lock"
mkdir "$scratch/aeglos"
tar -xf "$1/$archive" -C "$scratch/aeglos"
export GOWORK="$scratch/go.work"
go work init "$prover" "$scratch/aeglos"
go mod download
go mod verify
gnark=(github.com/consensys/gnark github.com/consensys/gnark-crypto)
workspace=$(go list -m "${gnark[@]}")
standalone=$(cd "$prover" && GOWORK=off go list -m "${gnark[@]}")
if [[ $workspace != "$standalone" ]]; then
    echo 'Aeglos must require the gnark versions of the prover module' >&2
    exit 1
fi
make -C "$scratch/aeglos" -j "${BUILD_JOBS:-4}" ARCH="$2" BUILD_DIR="$scratch/build" PREFIX="$scratch/native" install
PROVER_CGO=1 GOAMD64="${GOAMD64:-$PROVER_GPU_GOAMD64}" PROVER_BUILD_TAGS=aeglos \
    CGO_LDFLAGS="-L$scratch/native/lib -L/usr/local/cuda/lib64" sh "$prover/build-release.sh" "$3" "$prover"
