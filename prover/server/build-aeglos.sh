#!/usr/bin/env bash
set -euo pipefail
if [[ $# != 3 ]]; then
    echo "Usage: $0 AEGLOS_ARCHIVE_DIRECTORY (CUDA_ARCH | cpu) OUTPUT" >&2
    exit 1
fi
if [[ ! $2 =~ ^(sm_[0-9]+|cpu)$ ]]; then
    echo 'The target must be cpu or a GPU architecture such as sm_89' >&2
    exit 1
fi
prover=$(cd "$(dirname "$0")" && pwd)
# shellcheck source=/dev/null
source "$prover/release-build.env"
if [[ $2 == cpu ]]; then
    lock="$prover/prover/backend/aeglos-cpu-source.lock"
else
    lock="$prover/prover/backend/aeglos-source.lock"
fi
scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT
mkdir "$scratch/aeglos"
if [[ ${AEGLOS_UNPINNED:-} == 1 ]]; then
    echo 'AEGLOS_UNPINNED builds Aeglos from an unverified source tree' >&2
    cp -R "$1/." "$scratch/aeglos"
else
    (cd "$1" && sha256sum -c "$lock")
    read -r _ archive < "$lock"
    tar -xf "$1/$archive" -C "$scratch/aeglos"
fi
export GOWORK="$scratch/go.work"
go work init "$prover" "$scratch/aeglos"
# Workspace mode reaches a gnark tool module no source serves.
for module in "$prover" "$scratch/aeglos"; do
    (cd "$module" && GOWORK=off go mod download && GOWORK=off go mod verify)
done
gnark=(github.com/consensys/gnark github.com/consensys/gnark-crypto)
workspace=$(go list -m "${gnark[@]}")
standalone=$(cd "$prover" && GOWORK=off go list -m "${gnark[@]}")
if [[ $workspace != "$standalone" ]]; then
    echo 'Aeglos must require the gnark versions of the prover module' >&2
    exit 1
fi
if [[ $2 == cpu ]]; then
    make -C "$scratch/aeglos" -j "${BUILD_JOBS:-4}" CPU_BUILD_DIR="$scratch/build" cpu
    PROVER_CGO=1 PROVER_BUILD_TAGS=aeglos_cpu CGO_LDFLAGS="-L$scratch/build" sh "$prover/build-release.sh" "$3" "$prover"
else
    make -C "$scratch/aeglos" -j "${BUILD_JOBS:-4}" ARCH="$2" BUILD_DIR="$scratch/build" PREFIX="$scratch/native" install
    PROVER_CGO=1 GOAMD64="${GOAMD64:-$PROVER_GPU_GOAMD64}" PROVER_BUILD_TAGS=aeglos \
        CGO_LDFLAGS="-L$scratch/native/lib -L/usr/local/cuda/lib64" sh "$prover/build-release.sh" "$3" "$prover"
fi
