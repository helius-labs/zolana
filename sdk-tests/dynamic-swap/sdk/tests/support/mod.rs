use std::path::{Path, PathBuf};

use spr_program::{
    from_bytes,
    proof::compressed_proof,
    to_bytes,
    xark::{
        prover::{circuit_at, ProveError},
        Input,
    },
    CompressedProof, Field, ProgramProofInputs,
};
use spr_transaction::instructions::transact::PrivateTxHash;

pub fn field(bytes: &[u8; 32]) -> Field {
    from_bytes(bytes).unwrap()
}

pub fn bytes(value: &Field) -> [u8; 32] {
    to_bytes(value)
}

/// The private transaction hash over input and output utxo hashes.
pub fn private_tx_hash(inputs: &[Field], outputs: &[Field], blinding: &Field) -> Field {
    let inputs: Vec<_> = inputs.iter().map(bytes).collect();
    let outputs: Vec<_> = outputs.iter().map(bytes).collect();
    field(
        &PrivateTxHash::new(&inputs, &outputs, &bytes(blinding))
            .hash()
            .unwrap(),
    )
}

/// `just ensure-dynamic-swap-keys` builds each circuit and its test proving
/// key here.
fn artifacts(circuit: &str) -> PathBuf {
    std::env::var_os("ZOLANA_ZK_ARTIFACTS_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../target/zk/dynamic-swap-program")
        })
        .join(circuit)
}

fn proof_inputs<P: Input>(program: &P, public_hash: [u8; 32]) -> ProgramProofInputs {
    ProgramProofInputs::new(program, field(&public_hash))
}

/// Checks `program` against the built circuit's constraints. `public_hash` is
/// the hash the program's verifier computes from the public inputs, so a
/// rejection comes from the circuit's own checks.
pub fn check<P: Input>(
    circuit: &str,
    program: &P,
    public_hash: [u8; 32],
) -> Result<(), ProveError> {
    circuit_at(artifacts(circuit)).check(proof_inputs(program, public_hash))
}

/// Proves `program` with the built circuit's test proving key.
pub fn prove<P: Input>(circuit: &str, program: &P, public_hash: [u8; 32]) -> CompressedProof {
    let proof = circuit_at(artifacts(circuit))
        .prove(proof_inputs(program, public_hash))
        .unwrap();
    compressed_proof(&proof.proof).unwrap()
}
