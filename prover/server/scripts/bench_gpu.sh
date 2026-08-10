#!/bin/bash
# Prove-time benchmark over the pinned production circuits.
# Usage: scripts/bench_gpu.sh [cpu|gpu|both] [benchtime]
# gpu needs the ICICLE CUDA backend installed (cuda build); set
# ICICLE_BACKEND_INSTALL_DIR when the libs are not in the default location.
# Raw logs and parsed JSON land in bench-results/.
set -euo pipefail
cd "$(dirname "$0")/.."

mode="${1:-both}"
benchtime="${2:-10x}"
outdir="bench-results"
mkdir -p "$outdir"
stamp="$(date -u +%Y%m%dT%H%M%SZ)"

run() {
  local backend="$1"
  local tags=()
  [ "$backend" = gpu ] && tags=(-tags "cuda icicle")
  local log="$outdir/bench-$backend-$stamp.log"
  echo "== $backend -> $log"
  go test "${tags[@]}" -run '^$' -bench 'BenchmarkProve(Transfer|Merge)' \
    -benchtime "$benchtime" -timeout 6h \
    ./circuits/spp_transaction/shared ./circuits/spp_merge 2>&1 | tee "$log"
  python3 scripts/bench_parse.py "$log" > "$outdir/bench-$backend-$stamp.json"
}

case "$mode" in
  cpu) run cpu ;;
  gpu) run gpu ;;
  both) run cpu; run gpu ;;
  *) echo "usage: $0 [cpu|gpu|both] [benchtime]" >&2; exit 2 ;;
esac
