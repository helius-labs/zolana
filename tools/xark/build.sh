#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
    echo "Usage: tools/xark/build.sh <workspace Xark dependency path>" >&2
    exit 1
fi

xark_checkout=$(cd "$1" && pwd)
cargo build --release --manifest-path "$xark_checkout/Cargo.toml" -p xark-cli
"$xark_checkout/target/release/xark" --version
