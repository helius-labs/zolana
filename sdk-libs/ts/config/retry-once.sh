#!/usr/bin/env bash
# Run a command once; on failure print a visible warning and retry exactly once.
# Distinguishes a flake that recovered (warning + second pass) from a hard fail.
set -euo pipefail

if [ "$#" -lt 1 ]; then
  echo "usage: retry-once.sh <command> [args...]" >&2
  exit 2
fi

label="$*"
if "$@" ; then
  exit 0
fi

echo "::warning::live suite failed on attempt 1/2; retrying once: ${label}"
echo "retry-once: attempt 1/2 failed for: ${label}" >&2

if "$@" ; then
  echo "::warning::live suite passed on retry after flake: ${label}"
  echo "retry-once: attempt 2/2 passed for: ${label}" >&2
  exit 0
fi

echo "::error::live suite failed after 2 attempts: ${label}" >&2
exit 1
