#!/usr/bin/env bash
# Runs xtask from ZOLANA_XTASK_BIN when set, else through cargo.
set -euo pipefail
if [[ -n "${ZOLANA_XTASK_BIN:-}" ]]; then
  exec "$ZOLANA_XTASK_BIN" "$@"
fi
exec cargo run -q -p xtask -- "$@"
