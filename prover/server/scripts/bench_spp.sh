#!/usr/bin/env bash
# Benchmarks SPP transaction proving (solana + p256 ownership rails, every
# supported shape) and appends a dated results section to
# prover/server/BENCHMARKS.md. Proving time only: circuit compilation and
# Groth16 setup run before the benchmark timer starts.
#
# Usage: scripts/bench_spp.sh [benchtime]
#   benchtime  go -benchtime value per shape (default 5x)
set -euo pipefail

cd "$(dirname "$0")/.."

benchtime="${1:-5x}"
out_file="BENCHMARKS.md"

raw=$(go test ./prover/spp/prover/transaction/ -run '^$' \
    -bench BenchmarkProveByShape -benchtime "$benchtime" -timeout 120m \
    | tee /dev/stderr)

commit=$(git rev-parse --short HEAD)
branch=$(git rev-parse --abbrev-ref HEAD)
stamp=$(date -u '+%Y-%m-%d %H:%M UTC')
cpu=$(awk '/^cpu: / { sub(/^cpu: /, ""); print; exit }' <<< "$raw")

{
    echo
    echo "## ${stamp} — ${commit} (${branch}) — ${cpu} — benchtime ${benchtime}"
    echo
    echo "| Rail / shape | CPUs | Proving time (ms/op) | Constraints | MB/op | allocs/op |"
    echo "|---|---|---|---|---|---|"
    awk '/^BenchmarkProveByShape\// {
        name = $1
        sub(/^BenchmarkProveByShape\//, "", name)
        # go test appends GOMAXPROCS as a -N name suffix (omitted when it is 1).
        cpus = 1
        if (match(name, /-[0-9]+$/)) {
            cpus = substr(name, RSTART + 1)
            name = substr(name, 1, RSTART - 1)
        }
        printf "| %s | %s | %.1f | %s | %.1f | %s |\n", name, cpus, $3 / 1e6, $5, $7 / 1048576, $9
    }' <<< "$raw"
} >> "$out_file"

echo "Appended results to $(pwd)/${out_file}"
