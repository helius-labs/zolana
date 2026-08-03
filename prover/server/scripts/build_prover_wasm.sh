#!/usr/bin/env bash
# Builds the browser proving module: Zolana's gnark Groth16 proving path
# compiled to js/wasm, plus the matching Go runtime shim.
#
# Both outputs must ship together and must come from the same Go toolchain:
# wasm_exec.js implements the host side of Go's js/wasm ABI, which is not
# stable across releases. Copying it here rather than vendoring it keeps them
# in lockstep.
set -euo pipefail

server_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
repo_root="$(cd "$server_dir/../.." && pwd)"

# Both outputs default under target/. A caller that bundles the shim (a browser
# app importing it as a module) passes a second directory: Vite, for one, refuses
# to import anything out of its public dir, so the shim has to live in source
# while the .wasm stays a fetched asset.
out_dir="${1:-$repo_root/target/prover-wasm}"
shim_dir="${2:-$out_dir}"

mkdir -p "$out_dir" "$shim_dir"

goroot="$(go env GOROOT)"
# Go moved the wasm support files from misc/wasm to lib/wasm in 1.24.
shim=""
for candidate in "$goroot/lib/wasm/wasm_exec.js" "$goroot/misc/wasm/wasm_exec.js"; do
    if [[ -f "$candidate" ]]; then
        shim="$candidate"
        break
    fi
done
if [[ -z "$shim" ]]; then
    echo "error: wasm_exec.js not found under $goroot (looked in lib/wasm and misc/wasm)" >&2
    exit 1
fi

echo "building zolana-prover.wasm (GOOS=js GOARCH=wasm)"
cd "$server_dir"
GOOS=js GOARCH=wasm go build -trimpath -ldflags="-s -w" \
    -o "$out_dir/zolana-prover.wasm" ./cmd/prover-wasm/

cp "$shim" "$shim_dir/wasm_exec.js"

printf 'go: %s\nwasm: %s\nshim source: %s\n' \
    "$(go version)" \
    "$(du -h "$out_dir/zolana-prover.wasm" | cut -f1)" \
    "$shim" \
    > "$out_dir/BUILD_INFO.txt"

echo "wrote $out_dir/zolana-prover.wasm ($(du -h "$out_dir/zolana-prover.wasm" | cut -f1))"
echo "wrote $shim_dir/wasm_exec.js"
