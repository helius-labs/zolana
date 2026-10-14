pub use groth16_solana;
use groth16_solana::{
    decompression::{decompress_g1, decompress_g2},
    groth16::{Groth16Verifier, Groth16Verifyingkey},
};
use zolana_hasher::{Hasher, Poseidon};

const MAX_HASH_INPUTS: usize = 12;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VerifyError {
    PublicInputs,
    Proof,
}

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
            Field::Integer(value) => Ok(right_aligned(*value)),
            Field::Bool(value) => Ok(right_aligned(u128::from(*value))),
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

#[inline(never)]
pub fn verify_groth16(
    proof: &crate::CompressedProof,
    public_hash: [u8; 32],
    verifying_key: &Groth16Verifyingkey,
) -> Result<(), VerifyError> {
    if verifying_key.vk_commitment.is_some() {
        return Err(VerifyError::Proof);
    }
    let a = decompress_g1(&proof.a).map_err(|_| VerifyError::Proof)?;
    let b = decompress_g2(&proof.b).map_err(|_| VerifyError::Proof)?;
    let c = decompress_g1(&proof.c).map_err(|_| VerifyError::Proof)?;
    let public_inputs = [public_hash];
    Groth16Verifier::new(&a, &b, &c, &public_inputs, verifying_key)
        .map_err(|_| VerifyError::Proof)?
        .verify()
        .map_err(|_| VerifyError::Proof)
}

fn right_aligned(value: u128) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    for (target, source) in bytes.iter_mut().rev().zip(value.to_le_bytes()) {
        *target = source;
    }
    bytes
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
