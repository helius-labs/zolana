#!/usr/bin/env bash
# Regenerate the SPP nullifier batch-update verifying key after a change to the
# nullifier_batch_update circuit.
#
# Output: programs/shielded-pool/src/instructions/batch_update_nullifier_tree/verifying_key.rs
#
# Unlike the transact circuits (bsb22 with commitment), this circuit is verified
# by light_verifier with a STANDARD groth16-solana Groth16Verifyingkey, so the
# key is emitted with `xtask generate-vkey-rs --standard`. There are no e2e
# fixtures for the batch update (it is covered by Go unit tests), so only the
# embedded key is regenerated. Run from anywhere inside the repo.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

( cd prover/server && go build -o ../../target/prover-server . )
cargo build -q -p xtask
mkdir -p target/spp

stem=target/spp/spp-nullifier-update_40_10
rm -f "${stem}.key" "${stem}.vkey"
target/prover-server spp setup-nullifier-update --tree-height 40 --batch-size 10 \
    --output "${stem}.key" --output-vkey "${stem}.vkey"
./target/debug/xtask generate-vkey-rs --standard \
    --input-path "${stem}.vkey" \
    --output-path programs/shielded-pool/src/instructions/batch_update_nullifier_tree/verifying_key.rs

echo
echo "Regenerated nullifier verifying_key.rs. Sanity-check the circuit with:"
echo "  (cd prover/server && go test ./prover/spp/circuit/nullifier_batch_update/ ./prover/spp/prover/nullifier_batch_update/)"
