#!/usr/bin/env bash
set -euo pipefail

failed=0

# Every pathspec below must exist: a renamed or deleted directory would
# otherwise silently shrink the search surface to nothing.
require_paths() {
  local path
  for path in "$@"; do
    if [ ! -e "$path" ]; then
      echo "searched path is missing (renamed or deleted?): $path" >&2
      failed=1
    fi
  done
}

require_paths \
  Cargo.toml justfile program-tests sdk-libs/client sdk-libs/client/tests \
  sdk-tests/zk-program-swap/test \
  program-tests/spp-test-validator program-tests/spp-test-validator/tests \
  program-tests/zone-test-program program-tests/zone-test-program/tests

# git grep exits 0 on a match (a hygiene violation), 1 on no match (clean),
# and >1 on a fatal error such as an invalid pathspec; the fatal case must
# fail the script instead of passing as "no match".
report_matches() {
  local message=$1
  shift
  local status=0
  git grep -niE "$@" || status=$?
  if (( status == 0 )); then
    echo "$message" >&2
    failed=1
  elif (( status > 1 )); then
    echo "git grep failed (exit $status) while checking: $message" >&2
    failed=1
  fi
}

report_matches \
  "legacy scenario-test terminology or dependencies are not allowed" \
  '(cucumber|gherkin|(^|[^[:alnum:]_])bdd([^[:alnum:]_]|$))' -- \
  Cargo.toml ':(glob)**/Cargo.toml' justfile program-tests sdk-libs/client/tests \
  sdk-tests/zk-program-swap/test

if find program-tests sdk-libs/client/tests sdk-tests/zk-program-swap/test -type f \
  \( -path '*/features/*' -o -path '*/steps/*' -o -name '*.feature' \) -print \
  | grep -q .; then
  find program-tests sdk-libs/client/tests sdk-tests/zk-program-swap/test -type f \
    \( -path '*/features/*' -o -path '*/steps/*' -o -name '*.feature' \) -print
  echo "legacy scenario-test files are not allowed" >&2
  failed=1
fi

report_matches \
  "program tests must use the standard Rust test harness" \
  'harness[[:space:]]*=[[:space:]]*false' -- \
  program-tests sdk-libs/client sdk-tests/zk-program-swap/test

report_matches \
  "validator failures must inspect typed errors, not formatted strings" \
  '(assert_rpc_custom_error|expected custom program error.*got:|contains\(&code\.to_string\(\)\))' -- \
  program-tests/spp-test-validator/tests program-tests/zone-test-program/tests

report_matches \
  "test fixtures use Harness naming; World is a removed scenario-framework remnant" \
  '(LifecycleWorld|TransferWorld|MergeWorld|ZoneTransferWorld|ZoneAuthorityWorld|mod[[:space:]]+world)' -- \
  program-tests/spp-test-validator program-tests/zone-test-program sdk-libs/client/tests

# --- shielded-pool test-suite structural hygiene ---
#
# The shielded-pool suite maps each `[[test]]` binary directly to one leaf file
# under `tests/<domain>/<intent>.rs` and owns shared setup in the `src/support`
# library. These checks keep that mapping honest: no dangling manifest paths, no
# orphaned or wrapper leaves, and no committed runtime artifacts.
sp_dir=program-tests/shielded-pool
sp_manifest="$sp_dir/Cargo.toml"

declared_test_paths=$(grep -E '^path = "tests/' "$sp_manifest" | sed -E 's/^path = "([^"]+)"/\1/')

# (a) Every declared [[test]] path must exist on disk.
while IFS= read -r rel; do
  [ -z "$rel" ] && continue
  if [ ! -f "$sp_dir/$rel" ]; then
    echo "shielded-pool [[test]] path does not exist: $sp_dir/$rel" >&2
    failed=1
  fi
done <<EOF
$declared_test_paths
EOF

# (b) The obsolete `tests/common` `#[path]`-wrapper module tree must be gone
#     (shared setup now lives in `src/support`).
if [ -e "$sp_dir/tests/common" ]; then
  echo "obsolete tests/common wrapper module tree is still present under $sp_dir" >&2
  failed=1
fi

# (c) Every leaf under tests/ is either a declared [[test]] path or a submodule
#     intentionally included by one (ordinary `mod` or an explicit `#[path]`).
#     Catches orphaned files left behind by a move and re-introduced wrappers.
while IFS= read -r leaf; do
  rel=${leaf#"$sp_dir/"}
  if printf '%s\n' "$declared_test_paths" | grep -qxF "$rel"; then
    continue
  fi
  base=$(basename "$leaf")
  stem=${base%.rs}
  if grep -rqE "(#\[path = \"[^\"]*${base}\"\]|^[[:space:]]*mod[[:space:]]+${stem};)" "$sp_dir/tests"; then
    continue
  fi
  echo "orphan shielded-pool test leaf (neither a [[test]] nor included by one): $leaf" >&2
  failed=1
done < <(find "$sp_dir/tests" -name '*.rs')

# (d) Generated ledger/log runtime artifacts must never be tracked under a
#     source test package (they are gitignored; this catches an accidental add).
#     `*.proptest-regressions` corpora are NOT artifacts: TESTING.md documents
#     them as deliberately committed regression guards.
tracked_artifacts=$(git ls-files -- \
  'program-tests/**/test-ledger/**' 'program-tests/**/*.log' 2>/dev/null || true)
if [ -n "$tracked_artifacts" ]; then
  echo "generated runtime artifacts must not be committed under source test packages:" >&2
  printf '%s\n' "$tracked_artifacts" >&2
  failed=1
fi

if (( failed )); then
  exit 1
fi

echo "test hygiene checks passed"
