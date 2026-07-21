#!/usr/bin/env bash
set -euo pipefail

failed=0

report_matches() {
  local message=$1
  shift
  if git grep -niE "$@"; then
    echo "$message" >&2
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
  program-tests sdk-tests/zk-program-swap/test

report_matches \
  "validator failures must inspect typed errors, not formatted strings" \
  '(assert_rpc_custom_error|expected custom program error.*got:|contains\(&code\.to_string\(\)\))' -- \
  program-tests/spp-test-validator/tests program-tests/zone-test-program/tests

report_matches \
  "test fixtures use Harness naming; World is a removed scenario-framework remnant" \
  '(LifecycleWorld|TransferWorld|MergeWorld|ZoneTransferWorld|ZoneAuthorityWorld|mod[[:space:]]+world)' -- \
  program-tests/spp-test-validator program-tests/zone-test-program sdk-libs/client/tests

if (( failed )); then
  exit 1
fi

echo "test hygiene checks passed"
