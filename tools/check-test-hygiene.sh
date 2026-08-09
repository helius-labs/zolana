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

# Every check below searches this list, so a suite that moves out of it stops
# being checked silently. `zones/squads` is a nested workspace but the same git
# repository, so its tests are searched the same way.
test_roots=(
  program-tests
  sdk-libs/client/tests
  sdk-libs/keypair/tests
  sdk-libs/transaction/tests
  sdk-tests/zk-program-swap/test
  zones/squads/integration-tests
  zones/squads/interface/tests
  zones/squads/client/tests
)

# Test packages whose `[[test]]` binaries are pinned by manifest path.
manifest_pinned_suites=(
  program-tests/shielded-pool
  zones/squads/integration-tests
)

require_paths \
  Cargo.toml justfile sdk-libs/client \
  program-tests/spp-test-validator program-tests/spp-test-validator/tests \
  program-tests/ring-test-program program-tests/ring-test-program/tests \
  "${test_roots[@]}" "${manifest_pinned_suites[@]}"

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
  Cargo.toml ':(glob)**/Cargo.toml' justfile "${test_roots[@]}"

scenario_files=$(find "${test_roots[@]}" -type f \
  \( -path '*/features/*' -o -path '*/steps/*' -o -name '*.feature' \) -print)
if [ -n "$scenario_files" ]; then
  printf '%s\n' "$scenario_files" >&2
  echo "legacy scenario-test files are not allowed" >&2
  failed=1
fi

report_matches \
  "program tests must use the standard Rust test harness" \
  'harness[[:space:]]*=[[:space:]]*false' -- \
  sdk-libs/client "${test_roots[@]}"

report_matches \
  "validator failures must inspect typed errors, not formatted strings" \
  '(assert_rpc_custom_error|expected custom program error.*got:|contains\(&code\.to_string\(\)\))' -- \
  program-tests/spp-test-validator/tests program-tests/ring-test-program/tests

report_matches \
  "test fixtures use Harness naming; World is a removed scenario-framework remnant" \
  '(LifecycleWorld|TransferWorld|MergeWorld|RingTransferWorld|RingAuthorityWorld|mod[[:space:]]+world|_world[[:space:]]*:)' -- \
  program-tests/spp-test-validator program-tests/ring-test-program ':(glob)sdk-libs/*/tests/**'

# Manifest-pinned test-suite structural hygiene.
#
# These suites map each `[[test]]` binary directly to one leaf file under
# `tests/<domain>/<intent>.rs` and own shared setup in a library target. The
# checks keep that mapping honest: no dangling manifest paths, no orphaned or
# wrapper leaves, and no committed runtime artifacts.
for suite_dir in "${manifest_pinned_suites[@]}"; do
  declared_test_paths=$(grep -E '^path = "tests/' "$suite_dir/Cargo.toml" \
    | sed -E 's/^path = "([^"]+)"/\1/')

  # (a) Every declared [[test]] path must exist on disk.
  while IFS= read -r rel; do
    [ -z "$rel" ] && continue
    if [ ! -f "$suite_dir/$rel" ]; then
      echo "[[test]] path does not exist: $suite_dir/$rel" >&2
      failed=1
    fi
  done <<EOF
$declared_test_paths
EOF

  # (b) The obsolete `tests/common` `#[path]`-wrapper module tree must be gone
  #     (shared setup now lives in the package's library target).
  if [ -e "$suite_dir/tests/common" ]; then
    echo "obsolete tests/common wrapper module tree is still present under $suite_dir" >&2
    failed=1
  fi

  # (c) Every nested leaf under tests/ is either a declared [[test]] path or a
  #     submodule intentionally included by one (ordinary `mod` or an explicit
  #     `#[path]`). Catches orphaned files left behind by a move and
  #     re-introduced wrappers. Files directly under `tests/` are exempt, because
  #     cargo auto-discovers those as test binaries whether or not they are
  #     declared.
  while IFS= read -r leaf; do
    rel=${leaf#"$suite_dir/"}
    case "$rel" in
      tests/*/*) ;;
      *) continue ;;
    esac
    if printf '%s\n' "$declared_test_paths" | grep -qxF "$rel"; then
      continue
    fi
    base=$(basename "$leaf")
    # A `mod.rs` is reached through its directory's name, not its own.
    if [ "$base" = mod.rs ]; then
      stem=$(basename "$(dirname "$leaf")")
    else
      stem=${base%.rs}
    fi
    # The inclusion reference must live in the leaf's own directory or its parent
    # (the `<domain>.rs` sibling that declares the leaf's module): a same-stem
    # module in a sibling directory does not include this leaf.
    if grep -rqE "(#\[path = \"[^\"]*${base}\"\]|^[[:space:]]*(pub(\([^)]*\))?[[:space:]]+)?mod[[:space:]]+${stem};)" \
      "$(dirname "$leaf")" "$(dirname "$(dirname "$leaf")")" 2>/dev/null; then
      continue
    fi
    echo "orphan test leaf (neither a [[test]] nor included by one): $leaf" >&2
    failed=1
  done < <(find "$suite_dir/tests" -name '*.rs')
done

# (d) Generated ledger/log runtime artifacts must never be tracked under a
#     source test package (they are gitignored; this catches an accidental add).
#     `*.proptest-regressions` corpora are NOT artifacts: TESTING.md documents
#     them as deliberately committed regression guards.
tracked_artifacts=$(git ls-files -- \
  'program-tests/**/test-ledger/**' 'program-tests/**/*.log' \
  'zones/**/test-ledger/**' 'zones/**/*.log' 2>/dev/null || true)
if [ -n "$tracked_artifacts" ]; then
  echo "generated runtime artifacts must not be committed under source test packages:" >&2
  printf '%s\n' "$tracked_artifacts" >&2
  failed=1
fi

# --- invariants ledger consistency ---
#
# (e) The README's tallies must match the ledger files: per-file
#     total/ticked/N-A, the global totals, and the severity counts.
# (f) Every `Covered by:` citation must name something that exists: in the
#     cited file when a repo-relative path is given, anywhere in the tree
#     otherwise (the fallback keeps free-form citations of constants and
#     fields honest without demanding a test-function shape).
inv_dir=program-tests/shielded-pool/invariants
inv_readme="$inv_dir/README.md"
require_paths "$inv_dir" "$inv_readme"

# Every ledger in the directory, so a new one is counted the day it lands.
inv_files=$(find "$inv_dir" -maxdepth 1 -name '*.md' ! -name 'README.md' ! -name 'PROMPT.md' \
  -exec basename {} .md \; | sort)

# Per file: total entries, ticked [x], companion [~], N/A entries (block
# contains the marker). Prints "total ticked comp na".
inv_tally() {
  awk '
    function flush() { if (seen && block ~ /Not applicable post-PR164/) na++ }
    /^- \[[ x]\] \*\*INV-/ {
      flush(); total++; seen=1; block=""
      if ($0 ~ /^- \[x\]/) tick++
      next
    }
    /^- \[~\] \*\*INV-/ {
      flush(); total++; comp++; seen=1; block=""
      next
    }
    { block = block $0 "\n" }
    END { flush(); printf "%d %d %d %d\n", total+0, tick+0, comp+0, na+0 }
  ' "$inv_dir/$1.md"
}

tally_mismatch() {
  echo "invariants tally mismatch ($1): README claims $2, ledger computes $3" >&2
  failed=1
}

sum_total=0; sum_tick=0; sum_comp=0; sum_na=0
for name in $inv_files; do
  read -r total tick comp na <<< "$(inv_tally "$name")"
  partial=$(( total - tick - comp - na ))
  sum_total=$(( sum_total + total ))
  sum_tick=$(( sum_tick + tick ))
  sum_comp=$(( sum_comp + comp ))
  sum_na=$(( sum_na + na ))
  # README per-file cell: "name C/P/COMP/N"
  claim=$(grep -oE "${name} [0-9]+/[0-9]+/[0-9]+/[0-9]+" "$inv_readme" | head -1 | awk '{print $2}' | tr '/' ' ')
  if [ -z "$claim" ]; then
    tally_mismatch "$name" "no per-file cell" "$total/$partial/$comp/$na"
  else
    read -r c p m n <<< "$claim"
    [ "$c" = "$tick" ] && [ "$p" = "$partial" ] && [ "$m" = "$comp" ] && [ "$n" = "$na" ] || \
      tally_mismatch "$name" "$c/$p/$m/$n" "$tick/$partial/$comp/$na"
  fi
done

readme_number() { sed -nE "$2" "$inv_readme" | head -1; }

claim_total=$(readme_number x 's/^- Total invariants: ([0-9]+).*/\1/p')
[ "$claim_total" = "$sum_total" ] || tally_mismatch "Total invariants" "$claim_total" "$sum_total"
claim_covered=$(readme_number x 's/^- Covered: ([0-9]+) \/ ([0-9]+).*/\1/p')
[ "$claim_covered" = "$sum_tick" ] || tally_mismatch "Covered" "$claim_covered" "$sum_tick"
claim_companion=$(readme_number x 's/^- Covered on companion (security )?branches.*: ([0-9]+).*/\2/p')
[ "$claim_companion" = "$sum_comp" ] || tally_mismatch "Companion" "$claim_companion" "$sum_comp"
claim_na=$(readme_number x 's/^- Not applicable post-PR164: ([0-9]+).*/\1/p')
[ "$claim_na" = "$sum_na" ] || tally_mismatch "Not applicable" "$claim_na" "$sum_na"
claim_partial=$(readme_number x 's/^- Partial: ([0-9]+).*/\1/p')
claim_pointer=$(readme_number x 's/^- Pointer: ([0-9]+).*/\1/p')
# The pointer count comes from the ledger (entries marked "pointer entry"),
# not from the README claim; Partial is computed from the ledger and both
# are diffed against the README, never one from the other.
ledger_pointer=0
for name in $inv_files; do
  n=$(grep -c "pointer entry" "$inv_dir/$name.md" || true)
  ledger_pointer=$(( ledger_pointer + n ))
done
[ "${claim_pointer:-0}" = "$ledger_pointer" ] || \
  tally_mismatch "Pointer" "${claim_pointer:-0}" "$ledger_pointer"
# The ledger cannot tell a partial entry from an untested one, so the README
# states them apart and the sum is what the ledger can check.
claim_untested=$(readme_number x 's/^- Not covered: ([0-9]+).*/\1/p')
claim_open=$(( ${claim_partial:-0} + ${claim_untested:-0} ))
computed_partial=$(( sum_total - sum_tick - sum_comp - sum_na - ledger_pointer ))
[ "$claim_open" = "$computed_partial" ] || \
  tally_mismatch "Partial plus not covered" "$claim_open" "$computed_partial"

for sev in Critical High Medium; do
  computed=0
  for name in $inv_files; do
    n=$(grep -cE "^  - Severity: ${sev}" "$inv_dir/$name.md" || true)
    computed=$(( computed + n ))
  done
  claim=$(readme_number x "s/^- ${sev}[^0-9]*: ([0-9]+).*/\\1/p")
  [ "$claim" = "$computed" ] || tally_mismatch "Severity $sev" "$claim" "$computed"
done

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

# (g) N/A claims of removal must hold. When a `Not applicable post-PR164`
# note claims a backticked symbol removed (the removal verb within ~70 chars
# after the token), that symbol must not appear in `programs/shielded-pool/src`
# code (comment lines do not count). Only snake_case and `::`-path tokens are
# checked (fields/functions/variant paths): bare CamelCase tokens are type
# names that legitimately exist (e.g. `OwnerTag`, `TransactProof`). Catches a
# stale N/A that outlived the code it describes (see INV-TRANSACT-14).
na_fail=0
na_notes=$(grep -h "Not applicable post-PR164" "$inv_dir"/*.md || true)
while IFS= read -r line; do
  [ -z "$line" ] && continue
  while IFS= read -r tok; do
    [ -z "$tok" ] && continue
    case "$tok" in
      *\**) continue ;;  # glob families (e.g. MERGE_ENCRYPTED_UTXO_*)
    esac
    [[ "$tok" =~ ^[a-z_][a-z0-9_]*$ || "$tok" =~ :: ]] || continue
    after=${line#*\`$tok\`}
    window=${after:0:70}
    printf '%s' "$window" | grep -qiE 'removed|deleted|retired|no longer|gone' || continue
    hits=$(git grep -nF "$tok" -- programs/shielded-pool/src | awk -F: '$3 !~ /^ *\/\//' || true)
    if [ -n "$hits" ]; then
      echo "invariants N/A note claims '$tok' was removed, but it exists in programs/shielded-pool/src:" >&2
      printf '%s\n' "$hits" >&2
      na_fail=1
    fi
  done <<< "$(printf '%s' "$line" | grep -oE '`[^`]+`' | tr -d '`' || true)"
done <<< "$na_notes"
if (( na_fail )); then
  failed=1
fi

# zones/squads is its own workspace and re-pins the shared external crates by
# hand. Two groth16-solana revisions in one graph compile until a verifying key
# crosses the boundary, then fail as "a different Groth16Verifyingkey", so the
# pins are compared here rather than at that call site. Every shared crate is
# compared, not only groth16-solana. The nested manifest states that its
# versions mirror the root, and a type from any shared crate can cross the same
# boundary.
#
# Only crates a member of the nested workspace actually consumes
# (`{ workspace = true }`) are compared. An entry no member inherits pins
# nothing, so a stale version there is dead text rather than a build hazard.
workspace_pin() {
  awk -v want="$2" '
    /^\[workspace\.dependencies\]/ { in_deps = 1; next }
    /^\[/ { in_deps = 0 }
    in_deps && $1 == want && $2 == "=" {
      if ($0 ~ /path[[:space:]]*=/) exit
      if (match($0, /rev[[:space:]]*=[[:space:]]*"[^"]+"/)) {
        pin = substr($0, RSTART, RLENGTH)
      } else if (match($0, /version[[:space:]]*=[[:space:]]*"[^"]+"/)) {
        pin = substr($0, RSTART, RLENGTH)
      } else if (match($0, /=[[:space:]]*"[^"]+"/)) {
        pin = substr($0, RSTART, RLENGTH)
      } else {
        exit
      }
      gsub(/^[^"]*"|"$/, "", pin)
      # "3.2" and "3.2.0" are the same requirement, so compare three components.
      if (pin ~ /^[0-9]+\.[0-9]+$/) pin = pin ".0"
      print pin
      exit
    }
  ' "$1"
}

consumed_shared_deps=$(grep -hoE '^[a-z0-9_-]+ = \{ workspace = true' zones/squads/*/Cargo.toml \
  | awk '{ print $1 }' | sort -u)

while IFS= read -r dep; do
  [ -z "$dep" ] && continue
  root_pin=$(workspace_pin Cargo.toml "$dep")
  squads_pin=$(workspace_pin zones/squads/Cargo.toml "$dep")
  [ -n "$root_pin" ] && [ -n "$squads_pin" ] || continue
  if [ "$root_pin" != "$squads_pin" ]; then
    echo "$dep pin differs between workspaces:" >&2
    echo "  Cargo.toml              $root_pin" >&2
    echo "  zones/squads/Cargo.toml $squads_pin" >&2
    failed=1
  fi
done <<EOF
$consumed_shared_deps
EOF

if (( failed )); then
  exit 1
fi

echo "test hygiene checks passed"
