#!/usr/bin/env bash

set -euo pipefail

cd "$(dirname "$0")/.."

BENCHTIME="${BENCHTIME:-1x}"
COUNT="${COUNT:-1}"

go test ./prover/spp/prover/transaction \
  -run '^$' \
  -bench '^BenchmarkProveByShape$' \
  -benchmem \
  -benchtime="$BENCHTIME" \
  -count="$COUNT" \
  -timeout 30m \
  "$@"
