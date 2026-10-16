//! On-chain verification of a ZK program proof. A program's public inputs hash
//! into its one public input, the public hash; the Groth16 verification itself
//! is the zk DSL's.

use groth16_solana::groth16::Groth16Verifyingkey;
use zolana_hasher::{Hasher, Poseidon};
use zolana_zk_dsl::verifier::{boolean, integer};
pub use zolana_zk_dsl::verifier::{groth16_solana, VerifyError};

const MAX_HASH_INPUTS: usize = 12;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Field<'a> {
    Integer(u128),
    Bool(bool),
    Hash(&'a [u8; 32]),
    Array(&'a [Field<'a>]),
}

impl Field<'_> {
    fn value(&self) -> Result<[u8; 32], VerifyError> {
        match self {
            Field::Integer(value) => Ok(integer(*value)),
            Field::Bool(value) => Ok(boolean(*value)),
            Field::Hash(hash) => Ok(**hash),
            Field::Array(items) => poseidon(items.iter().map(Field::value)),
        }
    }
}

pub fn public_hash(fields: &[Field], private_tx_hash: &[u8; 32]) -> Result<[u8; 32], VerifyError> {
    poseidon(
        fields
            .iter()
            .map(Field::value)
            .chain(core::iter::once(Ok(*private_tx_hash))),
    )
}

/// Verifies a ZK program proof, whose one public input is its public hash.
pub fn verify_groth16(
    proof: &crate::CompressedProof,
    public_hash: [u8; 32],
    verifying_key: &Groth16Verifyingkey,
) -> Result<(), VerifyError> {
    zolana_zk_dsl::verifier::verify_groth16(proof, &[public_hash], verifying_key)
}

fn poseidon(
    values: impl Iterator<Item = Result<[u8; 32], VerifyError>>,
) -> Result<[u8; 32], VerifyError> {
    let mut buffer = [[0u8; 32]; MAX_HASH_INPUTS];
    let mut count = 0usize;
    for value in values {
        let slot = buffer.get_mut(count).ok_or(VerifyError::PublicInputs)?;
        *slot = value?;
        count += 1;
    }
    let mut inputs: [&[u8]; MAX_HASH_INPUTS] = [&[]; MAX_HASH_INPUTS];
    for (input, value) in inputs.iter_mut().zip(&buffer) {
        *input = value.as_slice();
    }
    let inputs = inputs.get(..count).ok_or(VerifyError::PublicInputs)?;
    Poseidon::hashv(inputs).map_err(|_| VerifyError::PublicInputs)
}
