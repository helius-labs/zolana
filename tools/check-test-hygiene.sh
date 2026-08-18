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
  sdk-libs/keypair/tests sdk-libs/transaction/tests \
  sdk-tests/zk-program-swap/test \
  program-tests/spp-test-validator program-tests/spp-test-validator/tests \
  program-tests/ring-test-program program-tests/ring-test-program/tests

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
  Cargo.toml ':(glob)**/Cargo.toml' justfile program-tests \
  sdk-libs/client/tests sdk-libs/keypair/tests sdk-libs/transaction/tests \
  sdk-tests/zk-program-swap/test

if find program-tests sdk-libs/client/tests sdk-libs/keypair/tests \
  sdk-libs/transaction/tests sdk-tests/zk-program-swap/test -type f \
  \( -path '*/features/*' -o -path '*/steps/*' -o -name '*.feature' \) -print \
  | grep -q .; then
  find program-tests sdk-libs/client/tests sdk-libs/keypair/tests \
    sdk-libs/transaction/tests sdk-tests/zk-program-swap/test -type f \
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
  program-tests/spp-test-validator/tests program-tests/ring-test-program/tests

report_matches \
  "test fixtures use Harness naming; World is a removed scenario-framework remnant" \
  '(LifecycleWorld|TransferWorld|MergeWorld|RingTransferWorld|RingAuthorityWorld|mod[[:space:]]+world|_world[[:space:]]*:)' -- \
  program-tests/spp-test-validator program-tests/ring-test-program ':(glob)sdk-libs/*/tests/**'


# --- test-suite structural hygiene ---
#
# The suites are auto-discovered: every `tests/*.rs` is one binary named after
# the file. That removes the check this section used to carry -- diffing
# `[[test]]` declarations against the tree -- because a file under `tests/`
# cannot fail to become a target. The ten gated suites are still declared, since
# `required-features` needs a block, but declaring one overrides the inferred
# target rather than adding a second, and a gate that goes missing leaves the
# suite running in the fast tier rather than vanishing.
#
# One surface still needs checking. A file in a *subdirectory* of `tests/` is not
# auto-discovered, so it runs only if a target pulls it in as a module -- today
# `shielded-pool/tests/localnet_photon/`, reached through `#[path]` from the
# suite root.
while IFS= read -r leaf; do
  [ -z "$leaf" ] && continue
  base=$(basename "$leaf")
  if [ "$base" = "mod.rs" ]; then
    # `tests/common/mod.rs` names its module after the directory, and is
    # included by sibling suites as `mod common;`.
    stem=$(basename "$(dirname "$leaf")")
  else
    stem=${base%.rs}
  fi
  if grep -rqE "(#\[path = \"[^\"]*${base}\"\]|^[[:space:]]*mod[[:space:]]+${stem};)" \
    "$(dirname "$leaf")" "$(dirname "$(dirname "$leaf")")" 2>/dev/null; then
    continue
  fi
  echo "test leaf in a tests/ subdirectory is reached by no target: $leaf" >&2
  failed=1
done < <(find program-tests -path '*/tests/*/*.rs')

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


# --- invariants ledger consistency ---
#
# The ledger maps each program invariant to the test that proves it. It is the
# substitute for coverage on the surface llvm-cov cannot see: the program runs
# inside the SVM, so these citations are what connect an invariant to its proof,
# and one naming something that no longer exists reads as a green checkmark
# against an invariant nothing tests.
#
# Only that is checked. The README's tallies and the prose of a retired entry
# were checked here too; both are bookkeeping about the bookkeeping, and a wrong
# count misleads nobody about whether an invariant is tested.
inv_dir=program-tests/shielded-pool/invariants
require_paths "$inv_dir"

# (f) Covered-by citations. A `Covered by:` line must carry at least one
# backticked token (otherwise the citation is invisible to this check);
# tokens after a repo-relative file path must exist in that file; other
# identifier tokens must be a real function somewhere. `Cross-branch
# coverage:` lines are the explicit companion-branch label and skip this
# check entirely.
covered_by_fail=0
bad_citations=""
covered_lines=$(grep -hE 'Covered by:|Cross-branch coverage:' "$inv_dir"/*.md || true)
while IFS= read -r line; do
  case "$line" in
    *Cross-branch\ coverage:*) continue ;;  # explicit companion-branch label
  esac
  tokens=$(printf '%s' "$line" | grep -oE '`[^`]+`' | tr -d '`' || true)
  if [ -z "$tokens" ]; then
    echo "invariants Covered-by line has no backticked citation: $line" >&2
    covered_by_fail=1
    continue
  fi
  current_file=""
  while IFS= read -r tok; do
    [ -z "$tok" ] && continue
    case "$tok" in
      *::*|*\ *|*\(*) continue ;;  # type paths, prose, calls
    esac
    if [[ "$tok" == *.rs || "$tok" == *.go ]]; then
      if [ -f "$tok" ]; then
        current_file="$tok"
      else
        # Relative citation (e.g. `merge/account.rs`): resolve via git.
        current_file=$(git ls-files | grep -E "/${tok}$" | head -1 || true)
      fi
      continue
    fi
    # Identifier token: only check test-shaped names.
    [[ "$tok" =~ ^[a-z_][a-z0-9_]*$ || "$tok" =~ ^Test[A-Za-z0-9]+$ ]] || continue
    if [ -n "$current_file" ] && grep -qF "$tok" "$current_file"; then
      continue
    fi
    # Not a bare substring: the name must be a real function somewhere
    # (a test fn or a cited impl fn), not a constant or a comment mention.
    if ! git grep -qE "fn ${tok}\(|func ${tok}\(" -- '*.rs' '*.go'; then
      bad_citations="${bad_citations}  $tok (line: $line)\n"
      covered_by_fail=1
    fi
  done <<< "$tokens"
done <<< "$covered_lines"
if [ -n "$bad_citations" ]; then
  printf "invariants Covered-by references not found:\n$bad_citations" >&2
fi
if (( covered_by_fail )); then
  failed=1
fi

if (( failed )); then
  exit 1
fi

echo "test hygiene checks passed"
