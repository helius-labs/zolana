//! Golden digests pin the exported R1CS of circuits too large to derive by
//! hand. A changed digest means the circuit changed: re-derive the counts and
//! the equivalence checks before pinning the new value.

use sha2::{Digest, Sha256};
use zolana_program::ZkCircuit;

use super::fixture::{export, picus_export};

pub fn sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

pub fn r1cs_digest<F: ZkCircuit>() -> String {
    sha256(&export::<F>())
}

pub fn picus_r1cs_digest<F: ZkCircuit>() -> String {
    sha256(&picus_export::<F>())
}
