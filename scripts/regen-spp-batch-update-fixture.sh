#!/usr/bin/env bash
# Regenerate the forester batch-update (Light address-append) e2e fixture.
#
# Output: program-tests/shielded-pool/tests/fixtures/batch_update.json
#
# Unlike the transact vkeys, this proof is built against Light's COMMITTED
# address-append proving key (prover/server/proving-keys/batch_address-append_40_10.key,
# paired with the on-chain VK in the privacy-program-libs verifier), so it only
# needs regenerating if the queued values or the circuit change — not on a
# transact-circuit change.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

key=prover/server/proving-keys/batch_address-append_40_10.key
out=program-tests/shielded-pool/tests/fixtures/batch_update.json
if [[ ! -f "$key" ]]; then
    echo "missing $key (Light address-append proving key)" >&2
    exit 1
fi

# The fixtures subcommand only exists under the spp_e2e_fixtures build tag.
( cd prover/server && go build -tags spp_e2e_fixtures -o ../../target/prover-server . )
target/prover-server spp batch-update-fixture --proving-key "$key" --output "$out"
echo "Regenerated $out"
