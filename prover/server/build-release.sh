#!/bin/sh
set -eu

# shellcheck source=/dev/null
. "$(dirname "$0")/release-build.env"

if [ -n "$(go env GOFLAGS)" ]; then
    echo 'Release builds require empty GOFLAGS' >&2
    exit 1
fi

CGO_ENABLED="${PROVER_CGO:-0}" GOAMD64="${GOAMD64:-$PROVER_RELEASE_GOAMD64}" go build -tags "${PROVER_BUILD_TAGS:-}" -trimpath -pgo="${PROVER_PGO:-$PROVER_RELEASE_PGO}" -ldflags='-s -w -buildid=' -o "${1:-light-prover}" "${2:-.}"
