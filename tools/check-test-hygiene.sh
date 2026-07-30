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
  program-tests/spp-test-validator/tests program-tests/zone-test-program/tests

report_matches \
  "test fixtures use Harness naming; World is a removed scenario-framework remnant" \
  '(LifecycleWorld|TransferWorld|MergeWorld|ZoneTransferWorld|ZoneAuthorityWorld|mod[[:space:]]+world|_world[[:space:]]*:)' -- \
  program-tests/spp-test-validator program-tests/zone-test-program ':(glob)sdk-libs/*/tests/**'

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
  # The inclusion reference must live in the leaf's own directory or its parent
  # (the `<domain>.rs` sibling that declares the leaf's module): a same-stem
  # module in a sibling directory does not include this leaf.
  if grep -rqE "(#\[path = \"[^\"]*${base}\"\]|^[[:space:]]*mod[[:space:]]+${stem};)" \
    "$(dirname "$leaf")" "$(dirname "$(dirname "$leaf")")" 2>/dev/null; then
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

inv_files="transact deposit merge tree protocol-config zone-config spl event cross-cutting"

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
claim_companion=$(readme_number x 's/^- Covered on companion security branches.*: ([0-9]+).*/\1/p')
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
computed_partial=$(( sum_total - sum_tick - sum_comp - sum_na - ledger_pointer ))
[ "$claim_partial" = "$computed_partial" ] || \
  tally_mismatch "Partial" "$claim_partial" "$computed_partial"

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

if (( failed )); then
  exit 1
fi

echo "test hygiene checks passed"
