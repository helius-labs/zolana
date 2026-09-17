#!/bin/sh
set -eu

if [ -n "$(go env GOFLAGS)" ]; then
    echo 'Release builds require empty GOFLAGS' >&2
    exit 1
fi

CGO_ENABLED=0 go build -trimpath -pgo="${PROVER_PGO:-off}" -ldflags='-s -w -buildid=' -o "${1:-light-prover}" .
