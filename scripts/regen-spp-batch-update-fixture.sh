#!/usr/bin/env bash
# Regenerate the forester batch-update (Light address-append) e2e fixture.
#
# Output: program-tests/shielded-pool/tests/fixtures/batch_update.json
#
# The address-append proof is built against Light's COMMITTED proving key
# (prover/server/proving-keys/batch_address-append_40_10.key, paired with the
# on-chain VK in the privacy-program-libs verifier). The queue is seeded
# honestly: the fixture also bakes real Solana-rail transacts (5 SOL seed
# shields + 1 five-input SOL transfer) that the e2e submits in order to queue
# the exact values the append proof covers. The signer matches the transact
# fixtures (0x42*32 seed; user SOL account = its pubkey) so the same e2e payer
# can submit both. Regenerate if the queued values, the flow, or the Solana
# transact circuit change.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

key=prover/server/proving-keys/batch_address-append_40_10.key
spp_key_dir=target/spp
out=program-tests/shielded-pool/tests/fixtures/batch_update.json
# Matches regen-spp-transact-fixtures.sh: signer = Keypair::new_from_array([0x42; 32]).
signer_seed=4242424242424242424242424242424242424242424242424242424242424242
user_sol_account=2152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12

if [[ ! -f "$key" ]]; then
    echo "missing $key (Light address-append proving key)" >&2
    exit 1
fi
for shape in 1_2 5_3; do
    if [[ ! -f "${spp_key_dir}/spp_${shape}_solana.key" ]]; then
        echo "missing ${spp_key_dir}/spp_${shape}_solana.key (run regen-spp-transact-fixtures first)" >&2
        exit 1
    fi
done

# The fixtures subcommand only exists under the spp_e2e_fixtures build tag.
( cd prover/server && go build -tags spp_e2e_fixtures -o ../../target/prover-server . )
target/prover-server spp batch-update-fixture \
    --proving-key "$key" \
    --spp-key-dir "$spp_key_dir" \
    --solana-signer-seed-hex "$signer_seed" \
    --user-sol-account-hex "$user_sol_account" \
    --output "$out"
echo "Regenerated $out"
