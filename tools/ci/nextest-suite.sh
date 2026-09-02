#!/usr/bin/env bash
# Runs one nextest suite, from the ZOLANA_NEXTEST_ARCHIVE_DIR archive when set,
# else from source.
set -euo pipefail

if [[ -z "${ZOLANA_NEXTEST_ARCHIVE_DIR:-}" ]]; then
  exec cargo nextest run "$@"
fi

package=""
binaries=()
expr=""
run_args=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    -p)
      package="$2"
      shift 2
      ;;
    --test)
      binaries+=("binary($2)")
      shift 2
      ;;
    # Build-only flags, already baked into the archive.
    --features)
      shift 2
      ;;
    --release)
      shift
      ;;
    -E)
      expr="$2"
      shift 2
      ;;
    *)
      run_args+=("$1")
      shift
      ;;
  esac
done
if [[ -z "$package" ]]; then
  echo "nextest-suite.sh needs -p <package>" >&2
  exit 2
fi

selection=""
for term in ${binaries[@]+"${binaries[@]}"}; do
  if [[ -z "$selection" ]]; then
    selection="$term"
  else
    selection="$selection or $term"
  fi
done
if [[ -n "$selection" && -n "$expr" ]]; then
  selection="($selection) and ($expr)"
elif [[ -n "$expr" ]]; then
  selection="$expr"
fi

archive_args=(
  --archive-file "$ZOLANA_NEXTEST_ARCHIVE_DIR/$package.tar.zst"
  --workspace-remap "$PWD"
)
if [[ -n "$selection" ]]; then
  archive_args+=(-E "$selection")
fi
exec cargo nextest run "${archive_args[@]}" ${run_args[@]+"${run_args[@]}"}
