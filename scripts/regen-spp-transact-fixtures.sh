#!/usr/bin/env bash
# Regenerate the SPP transact verifying keys AND the e2e proof fixtures after a
# change to the transaction circuit.
#
# The committed verifying keys
#   programs/shielded-pool/src/instructions/transact/verifying_keys/spp_*.rs
# and the e2e fixtures
#   program-tests/shielded-pool/tests/fixtures/spp_e2e.json
# must be a matched set produced from ONE setup run (the fixture proofs are
# verified on-chain against those exact keys), so this script does both.
#
# Run from anywhere inside the repo on the tip branch (spp/7-demo), where both
# output paths exist. The transact circuit is bsb22 (commitment) groth16,
# verified on-chain by Groth16Verifier; vkeys are emitted by
# `xtask generate-vkey-rs` WITHOUT --standard (that flag is for the nullifier
# tree's standard-groth16 key; see regen-spp-nullifier-vkey.sh).
#
# The e2e-proof-bundle argument values mirror the litesvm test's hardcoded
# keypairs in program-tests/shielded-pool/tests/transact_e2e.rs:
#   solana signer seed   = 0x42 * 32  (fixture_payer = Keypair::new_from_array([0x42; 32]))
#   public SPL asset      = pubkey of Keypair::new_from_array([0x24; 32])  (test mint)
#   user SPL token acct   = pubkey of Keypair::new_from_array([0x22; 32])  (test user token)
#   spl token interface   = the mint's SPL vault PDA
#   user SOL account      = the signer pubkey
# The hex below are those derived pubkeys; they are stable. If the test changes
# its keypairs, re-read the values from the `assert_eq!` lines in that test.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

# The fixtures subcommand only exists under the spp_e2e_fixtures build tag.
( cd prover/server && go build -tags spp_e2e_fixtures -o ../../target/prover-server . )
cargo build -q -p xtask
mkdir -p target/spp

vkeys_dir=programs/shielded-pool/src/instructions/transact/verifying_keys
for shape in 2:2 1:2 3:3 5:3 1:8; do
    inp="${shape%%:*}"; outp="${shape##*:}"
    stem="target/spp/spp_${inp}_${outp}"
    rm -f "${stem}.key" "${stem}.vkey"
    target/prover-server spp setup --inputs "$inp" --outputs "$outp" \
        --output "${stem}.key" --output-vkey "${stem}.vkey"
    ./target/debug/xtask generate-vkey-rs \
        --input-path "${stem}.vkey" \
        --output-path "${vkeys_dir}/spp_${inp}_${outp}.rs"
done

target/prover-server spp e2e-proof-bundle \
    --keys-file target/spp/spp_1_2.key \
    --output program-tests/shielded-pool/tests/fixtures/spp_e2e.json \
    --solana-signer-seed-hex 4242424242424242424242424242424242424242424242424242424242424242 \
    --public-spl-asset-pubkey 58936604abda112bc94933569c82f8d0cc0ddf92a3f8329f2f448f7f484a594c \
    --user-sol-account-hex 2152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12 \
    --user-spl-token-account-hex a09aa5f47a6759802ff955f8dc2d2a14a5c99d23be97f864127ff9383455a4f0 \
    --spl-token-interface-hex c5eb0fa5bf9f602e6b7336a388d438c4d6107de40ea83f72bc69639f97dc84c4

echo
echo "Regenerated transact vkeys + spp_e2e.json. Now rebuild the program and test:"
echo "  cargo build-sbf --tools-version v1.54 --manifest-path programs/shielded-pool/Cargo.toml -- --features bpf-entrypoint"
echo "  cargo test -p shielded-pool-tests --test transact_e2e"
