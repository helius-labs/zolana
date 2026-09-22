#!/bin/sh
set -eu

. "$(dirname "$0")/release-build.env"

if [ -n "$(go env GOFLAGS)" ]; then
    echo 'Release builds require empty GOFLAGS' >&2
    exit 1
fi

CGO_ENABLED=0 GOAMD64="${GOAMD64:-$PROVER_RELEASE_GOAMD64}" go build -trimpath -pgo="${PROVER_PGO:-$PROVER_RELEASE_PGO}" -ldflags='-s -w -buildid=' -o "${1:-light-prover}" .
