//! On-chain verification of a ZK program proof. A program's public inputs hash
//! into its one public input, the public hash.

use groth16_solana::groth16::Groth16Verifyingkey;
use zolana_hasher::{Hasher, Poseidon};
pub use groth16_solana;
pub use zolana_hasher::primitives::pack_be;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VerifyError {
    /// A public input or transaction commitment cannot be encoded.
    PublicInputs,
    /// The proof is malformed or does not verify under the key.
    Proof,
}

/// Allows instruction handlers to propagate verification failures with `?`.
impl From<VerifyError> for solana_program_error::ProgramError {
    fn from(error: VerifyError) -> Self {
        match error {
            VerifyError::PublicInputs => Self::InvalidInstructionData,
            VerifyError::Proof => Self::InvalidArgument,
        }
    }
}

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

pub fn public_hash(fields: &[Field], transaction_hash: &[u8; 32]) -> Result<[u8; 32], VerifyError> {
    poseidon(
        fields
            .iter()
            .map(Field::value)
            .chain(core::iter::once(Ok(*transaction_hash))),
    )
}

/// The one-field public commitment of a shielded address, including its viewer.
pub fn address_hash(
    owner_hash: &[u8; 32],
    viewing_pubkey: &[u8; 33],
) -> Result<[u8; 32], VerifyError> {
    let viewing_hash = zolana_hasher::primitives::hash_bytes(viewing_pubkey)
        .map_err(|_| VerifyError::PublicInputs)?;
    Poseidon::hashv(&[owner_hash.as_slice(), viewing_hash.as_slice()])
        .map_err(|_| VerifyError::PublicInputs)
}

/// Verifies a ZK program proof, whose one public input is its public hash.
pub fn verify_groth16(
    proof: &crate::CompressedProof,
    public_hash: [u8; 32],
    verifying_key: &Groth16Verifyingkey,
) -> Result<(), VerifyError> {
    verify_groth16_inputs(proof, &[public_hash], verifying_key)
}

pub fn verify_groth16_inputs<const N: usize>(
    proof: &crate::CompressedProof,
    public_inputs: &[[u8; 32]; N],
    verifying_key: &Groth16Verifyingkey,
) -> Result<(), VerifyError> {
    use groth16_solana::{decompression::{decompress_g1, decompress_g2}, groth16::Groth16Verifier};
    if verifying_key.vk_commitment.is_some() { return Err(VerifyError::Proof); }
    let a = decompress_g1(&proof.a).map_err(|_| VerifyError::Proof)?;
    let b = decompress_g2(&proof.b).map_err(|_| VerifyError::Proof)?;
    let c = decompress_g1(&proof.c).map_err(|_| VerifyError::Proof)?;
    Groth16Verifier::new(&a, &b, &c, public_inputs, verifying_key)
        .map_err(|_| VerifyError::Proof)?.verify().map_err(|_| VerifyError::Proof)
}

pub fn integer(value: u128) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    bytes[16..].copy_from_slice(&value.to_be_bytes());
    bytes
}

pub fn boolean(value: bool) -> [u8; 32] { integer(u128::from(value)) }

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
