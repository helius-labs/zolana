#!/usr/bin/env bash
# Runs xtask from SPR_XTASK_BIN when set, else through cargo.
set -euo pipefail
if [[ -n "${SPR_XTASK_BIN:-}" ]]; then
  exec "$SPR_XTASK_BIN" "$@"
fi
exec cargo run -q -p xtask -- "$@"
