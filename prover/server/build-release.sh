#!/bin/sh
set -eu

# shellcheck source=/dev/null
. "$(dirname "$0")/release-build.env"

if [ -n "$(go env GOFLAGS)" ]; then
    echo 'Release builds require empty GOFLAGS' >&2
    exit 1
fi

ldflags='-s -w -buildid='
if [ -n "${PROVER_EXTLDFLAGS:-}" ]; then
    ldflags="$ldflags -linkmode=external -extldflags=$PROVER_EXTLDFLAGS"
fi
CGO_ENABLED="${PROVER_CGO:-0}" GOAMD64="${GOAMD64:-$PROVER_RELEASE_GOAMD64}" go build -tags "${PROVER_BUILD_TAGS:-}" -trimpath -buildvcs=false -pgo="${PROVER_PGO:-$PROVER_RELEASE_PGO}" -ldflags="$ldflags" -o "${1:-light-prover}" "${2:-.}"
