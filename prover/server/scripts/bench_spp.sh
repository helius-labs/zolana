#!/usr/bin/env bash
# Benchmarks SPP transaction proving for every circuit variant (confidential,
# zone, zone_authority, p256) and records a dated results section in
# prover/server/BENCHMARKS.md.
#
# Each timed operation is one server-side proof against the committed,
# lockfile-pinned proving key: witness assembly plus groth16.Prove. Circuit
# compilation and Groth16 setup never run. Missing keys are downloaded and
# checked against prover/provingkeys/proving-keys.lock on first use, so the first
# run of a shape set is dominated by the download.
#
# Combinations that fail (for example a key whose constraint system no longer
# matches its pinned fingerprint) are named in the results section and make this
# script exit non-zero, but the rows that did run are still recorded.
#
# Usage: scripts/bench_spp.sh [benchtime]
#   benchtime  go -benchtime value per combination (default 5x)
#
# Env:
#   ZOLANA_BENCH_ALL_SHAPES=1  bench every pinned shape instead of the subset
#   ZOLANA_SPP_KEYS_DIR        proving-key directory (default prover/server/proving-keys)
set -euo pipefail

cd "$(dirname "$0")/.."

benchtime="${1:-5x}"
out_file="BENCHMARKS.md"
lockfile="prover/provingkeys/proving-keys.lock"

if ! grep -q '<!-- results -->' "$out_file"; then
    echo "${out_file} is missing the '<!-- results -->' marker" >&2
    exit 1
fi

raw_file=$(mktemp)
trap 'rm -f "$raw_file"' EXIT

# -v is required: without it, go test hides the skip lines that report which
# variant/shape combinations have no pinned key.
status=0
go test ./prover-test/spp/prover/transaction/ -run '^$' -v \
    -bench BenchmarkSppTransfer -benchtime "$benchtime" -timeout 120m \
    | tee "$raw_file" || status=$?

commit=$(git rev-parse --short HEAD)
branch=$(git rev-parse --abbrev-ref HEAD)
stamp=$(date -u '+%Y-%m-%d %H:%M UTC')
cpu=$(awk '/^cpu: / { sub(/^cpu: /, ""); print; exit }' "$raw_file")
# The proving-key version the rows belong to: rows from different prefixes are
# not comparable.
keys=$(sed -n 's/.*"prefix"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$lockfile" | head -1)
# go test appends GOMAXPROCS to every benchmark name as a -N suffix.
procs=$(awk '/ns\/op/ { if (match($1, /-[0-9]+$/)) { print substr($1, RSTART + 1); exit } }' "$raw_file")
shapes="representative subset"
if [[ "${ZOLANA_BENCH_ALL_SHAPES:-}" == "1" ]]; then
    shapes="all pinned shapes"
fi

# Collects one space-separated combination list per go test outcome marker.
combinations() {
    awk -v marker="$1" '
        index($0, "--- " marker ": BenchmarkSppTransfer/") {
            line = $0
            sub(/^[[:space:]]*--- [A-Z]+: BenchmarkSppTransfer\//, "", line)
            printf "%s ", line
        }
    ' "$raw_file"
}

section_file=$(mktemp)
trap 'rm -f "$raw_file" "$section_file"' EXIT
{
    echo
    echo "## ${stamp} — ${commit} (${branch}) — ${cpu} — benchtime ${benchtime}"
    echo
    echo "Proving keys \`${keys}\`, GOMAXPROCS ${procs:-unknown}, shapes: ${shapes}."
    echo
    echo "| Variant / shape | Proving time (ms/op) | Constraints | MB/op | allocs/op |"
    echo "|---|---|---|---|---|"
    awk '/^BenchmarkSppTransfer\// && /ns\/op/ {
        name = $1
        sub(/^BenchmarkSppTransfer\//, "", name)
        sub(/-[0-9]+$/, "", name)
        printf "| %s | %.1f | %s | %.1f | %s |\n", name, $3 / 1e6, $5, $7 / 1048576, $9
    }' "$raw_file"

    skipped=$(combinations SKIP)
    if [[ -n "$skipped" ]]; then
        echo
        echo "Skipped, no proving key pinned for the shape: ${skipped% }"
    fi
    failed=$(combinations FAIL)
    if [[ -n "$failed" ]]; then
        echo
        echo "FAILED, not measured: ${failed% }"
    fi
} > "$section_file"

# Newest first: insert directly below the marker rather than appending, which
# would bury each run under the legacy sections at the end of the file. The
# section is passed as a file because awk -v cannot carry embedded newlines.
tmp=$(mktemp)
awk -v section="$section_file" '
    { print }
    !inserted && index($0, "<!-- results -->") {
        while ((getline line < section) > 0) {
            print line
        }
        close(section)
        inserted = 1
    }
' "$out_file" > "$tmp"
mv "$tmp" "$out_file"

echo "Wrote results to $(pwd)/${out_file}"
if [[ "$status" -ne 0 ]]; then
    echo "go test reported failures; the results section names the failing combinations" >&2
fi
exit "$status"
