#!/usr/bin/env bash
# Assemble the FuzzCorp bundle for the shielded-pool harness.
#
# Expects the program artifacts to ALREADY be staged into ./programs and
# ./fixtures by the caller (CI does this from a fresh `just build-programs`).
# This script deliberately does not build them itself: the point of living in
# this repo is that every push recompiles the program and refuzzes it, so the
# build must be the repo's own rather than a copy that can drift.
set -euo pipefail

# Coverage gate: a symbols file with no DWARF still satisfies `[ -f ]` and still
# reports "not stripped" from `file`, then renders EMPTY coverage on the server
# while every CI step reports success. The server's complaint in that case is
# "SourcesOriginalPath ... does not match any source file", which reads like a path
# bug rather than a missing-debug-info bug. Require real compile units instead.
scout_has_dwarf() {
  so="$1"; dd=""
  command -v llvm-dwarfdump >/dev/null 2>&1 && dd=llvm-dwarfdump
  [ -z "$dd" ] && command -v dwarfdump >/dev/null 2>&1 && dd=dwarfdump
  if [ -z "$dd" ]; then
    echo "warning: no llvm-dwarfdump available; cannot verify DWARF in $so" >&2
    return 0
  fi
  n=$($dd --debug-info "$so" 2>/dev/null | grep -c DW_TAG_compile_unit)
  if [ "${n:-0}" -eq 0 ]; then
    echo "warning: $so carries NO DWARF (0 compile units) -- coverage would render" >&2
    echo "         empty. Build the program with CARGO_PROFILE_RELEASE_DEBUG=2 and" >&2
    echo "         CARGO_PROFILE_RELEASE_STRIP=none." >&2
    return 1
  fi
  echo "coverage: $(basename "$so") carries $n compile units"
  return 0
}

cd "$(dirname "$0")"

BUNDLE="${BUNDLE_DIR:-bundle}"
TEST_NAME="invariant_test"
REPO_ROOT="$(cd ../.. && pwd)"

# The runtime image and the cloud run one architecture, and cross-building
# through QEMU segfaults rustc. Detect rather than assume: an arm64 dev box and
# an amd64 GitHub runner each need a native binary.
case "$(uname -m)" in
  arm64|aarch64) ARCH="arm64" ;;
  x86_64|amd64)  ARCH="amd64" ;;
  *) echo "unsupported arch: $(uname -m)" >&2; exit 1 ;;
esac

for artifact in programs/shielded_pool_program.so fixtures/ring_test_program.so; do
  [ -f "$artifact" ] || { echo "missing $artifact -- build and stage the programs first" >&2; exit 1; }
done

# The harness resolves `programs/` and `fixtures/` relative to its working
# directory, which is what HarnessRunDirInBundle exists for.
RUN_DIR="harness"

# The unstripped SBF build. Optional to the driver: with it, coverage maps to
# source lines; without it, FUZZ_SYMBOLS is unset and coverage is PC-keyed. Warn
# rather than fail, so a bundle still builds where the debug artifact is absent.
SYMBOLS_JSON=""
if [ -f programs/shielded_pool_symbols.so ] && scout_has_dwarf programs/shielded_pool_symbols.so; then
  SYMBOLS_JSON='"SymbolsPathInBundle": "'"$RUN_DIR"'/programs/shielded_pool_symbols.so",'
else
  echo "note: no shielded_pool_symbols.so; coverage will be bytecode-level" >&2
fi

echo "building harness (arch=$ARCH)"
# FuzzCorp workers are linux/amd64 and this builds for the HOST. On a macOS/arm64
# box that silently yields a Mach-O arm64 binary: the bundle uploads, validates,
# and is then never picked up -- it fails as SILENCE, not as an error. CI runs on
# ubuntu-latest so it is correct there; refuse to produce a dead bundle elsewhere.
if [ "$(uname -s)" != "Linux" ] || [ "$(uname -m)" != "x86_64" ]; then
  echo "ERROR: the harness must be built on linux/x86_64 (host is $(uname -s)/$(uname -m))." >&2
  echo "       A host-arch binary uploads cleanly and is then never executed." >&2
  echo "       Build in CI, or inside a linux/amd64 container." >&2
  exit 1
fi
cargo build --release --features invariant_test

rm -rf "$BUNDLE"
mkdir -p "$BUNDLE/$RUN_DIR" "$BUNDLE/src"
cp "target/release/$TEST_NAME" "$BUNDLE/$RUN_DIR/"
cp -r programs fixtures idls "$BUNDLE/$RUN_DIR/"

# Sources for the coverage task's LCOV line mapping.
#
# The LCOV keys each line on DW_AT_comp_dir + the relative file, and the driver
# strips SourcesOriginalPath off that. comp_dir depends on HOW the program was
# built: `cargo build-sbf --debug` records workspace-relative paths, a plain
# release build records the absolute build directory (/home/runner/... on CI).
# Hardcoding the relative prefix therefore breaks the moment the build changes --
# and it fails SILENTLY as `lines_found: 0`, with the cover task reporting
# "SourcesOriginalPath ... does not match any source file". That is exactly what
# happened here. So READ comp_dir out of the artifact instead of assuming it.
cp -r "$REPO_ROOT/programs/shielded-pool/src/." "$BUNDLE/src/"

# Reading DW_AT_comp_dir is NOT enough: these SBF artifacts frequently carry no
# comp_dir at all, and the unit paths are a mix (programs/<crate>/src/..., bare
# src/lib.rs for dependencies, program-libs/...). Derive the prefix from the unit
# paths themselves, and FAIL if none matches rather than shipping a bundle whose
# coverage silently renders empty.
# The three coverage keys are ALL-OR-NOTHING. The server rejects the whole upload
# with "SourcesOriginalPath is required when SourcesPathInBundle is set" if the
# prefix comes out empty -- which is exactly what happened when the symbols were
# missing and the manifest still emitted the source keys with an empty value.
COVERAGE_JSON=""
if [ -n "${SYMBOLS_JSON:-}" ]; then
  if SRC_ORIG="$(./derive-sources-prefix.sh programs/shielded_pool_symbols.so \
                   'programs/shielded-pool/src/' 2>/dev/null)" && [ -n "$SRC_ORIG" ]; then
    echo "coverage: derived SourcesOriginalPath=$SRC_ORIG"
    COVERAGE_JSON="                            $SYMBOLS_JSON
                            \"SourcesPathInBundle\": \"src/\",
                            \"SourcesOriginalPath\": \"$SRC_ORIG\","
  else
    echo "ERROR: no line-table directory under programs/shielded-pool/src/ in the" >&2
    echo "       symbols. The cover task would fail with \"SourcesOriginalPath ... does" >&2
    echo "       not match any source file\" and the project would show lines_found: 0." >&2
    exit 1
  fi
else
  echo "note: no symbols staged -- shipping WITHOUT the coverage keys rather than" >&2
  echo "      with empty ones, which the server rejects outright." >&2
fi

# The profile also covers `program-libs/...`, which this prefix does not remap.
# Those records keep their key and resolve at the BUNDLE ROOT, so stage them there.
if [ -d "$REPO_ROOT/program-libs" ]; then
  mkdir -p "$BUNDLE/program-libs"
  cp -r "$REPO_ROOT/program-libs/." "$BUNDLE/program-libs/" 2>/dev/null || true
  echo "coverage: staged program-libs/ at the bundle root for the unprefixed records"
fi

# Invariants already reported upstream go here so campaigns surface only NEW
# signal. Empty today: nothing has been reported.
MUTE="${SCOUT_CHECK_MUTE:-}"
COMMIT="$(git rev-parse HEAD 2>/dev/null || echo 0000000)"

cat > "$BUNDLE/manifest.fc.json" <<MANIFEST
{
    "Version": 3,
    "Revision": { "Commit": "$COMMIT" },
    "Lineages": [
        {
            "Name": "shielded-pool",
            "Confs": [
                {
                    "Name": "shielded_pool_invariants",
                    "Driver": {
                        "Type": "crucible",
                        "Params": {
                            "BinaryPathInBundle": "$RUN_DIR/$TEST_NAME",
                            "HarnessRunDirInBundle": "$RUN_DIR",
$COVERAGE_JSON
                            "ExtraEnv": { "SCOUT_CHECK_MUTE": "$MUTE" }
                        }
                    },
                    "Architecture": { "Name": "$ARCH" },
                    "YieldTimeMinutes": 120,
                    "MemoryKiB": 4194304,
                    "Cores": 4
                }
            ]
        }
    ]
}
MANIFEST

echo "bundle staged at $BUNDLE"
find "$BUNDLE" -maxdepth 2 -not -path '*/.*' | sed 's/^/  /'
