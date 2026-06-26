use ark_bn254::Fr;
use ark_ff::PrimeField;
use groth16_solana::groth16::Groth16Verifyingkey;
use pinocchio::{error::ProgramError, ProgramResult};
use zolana_hasher::{Hasher, Sha256};
use zolana_interface::{
    error::ShieldedPoolError,
    instruction::instruction_data::transact::{TransactIxDataRef, TransactProof as ProofData},
    verifying_keys::{transfer_confidential_2_3, transfer_p256_confidential_2_3},
};

use crate::instructions::verifier;

pub const MAX_INPUTS: usize = 5;

pub const MAX_OUTPUTS: usize = 8;

pub const P256_OWNED_SIGNER: u8 = 255;

#[derive(Default, Debug)]
pub struct TransactProofInputs {
    pub utxo_roots: [[u8; 32]; MAX_INPUTS],
    pub nullifier_tree_roots: [[u8; 32]; MAX_INPUTS],
    pub input_owner_pk_hashes: [[u8; 32]; MAX_INPUTS],
    pub output_owner_pk_hashes: [[u8; 32]; MAX_OUTPUTS],
    pub p256_signing_pk_field: [u8; 32],
    pub external_data_hash: [u8; 32],
    pub spl_mint: Option<[u8; 32]>,
    pub program_id_hashchain: [u8; 32],
    pub payer_pubkey_hash: [u8; 32],
}

pub struct TransactProof<'a> {
    ix: &'a TransactIxDataRef<'a>,
    derived: TransactProofInputs,
}

impl<'a> TransactProof<'a> {
    pub fn new(ix: &'a TransactIxDataRef<'a>, derived: TransactProofInputs) -> Self {
        Self { ix, derived }
    }

    #[inline(never)]
    pub fn verify(&self) -> ProgramResult {
        let public_input_hash = self.public_input_hash()?;
        let is_p256 = self.is_p256();
        let verifying_key = select_verifying_key(self.n_inputs(), self.n_outputs(), is_p256)?;
        let encoding_err = ShieldedPoolError::InvalidTransactProofEncoding;
        let verify_err = ShieldedPoolError::TransactProofVerificationFailed;
        // The proof variant must agree with the rail derived from the inputs: the
        // eddsa rail is vanilla Groth16 (no commitment), the P256 rail is
        // BSB22-committed. Any mismatch is rejected before verification.
        let proof = match (&self.ix.proof, is_p256) {
            (ProofData::Eddsa { a, b, c }, false) => verifier::CompressedGroth16Proof {
                a,
                b,
                c,
                commitment: None,
            },
            (
                ProofData::P256 {
                    a,
                    b,
                    c,
                    commitment,
                    commitment_pok,
                },
                true,
            ) => verifier::CompressedGroth16Proof {
                a,
                b,
                c,
                commitment: Some((commitment, commitment_pok)),
            },
            _ => return Err(ShieldedPoolError::MismatchedTransactProofRail.into()),
        };
        verifier::verify_groth16(
            proof,
            public_input_hash,
            verifying_key,
            encoding_err,
            verify_err,
        )
    }

    fn n_inputs(&self) -> usize {
        self.ix.inputs.len()
    }

    fn n_outputs(&self) -> usize {
        self.ix.output_utxo_hashes.len()
    }

    fn is_p256(&self) -> bool {
        self.ix
            .inputs
            .iter()
            .any(|input| input.eddsa_signer_index == P256_OWNED_SIGNER)
    }

    fn public_input_hash(&self) -> Result<[u8; 32], ProgramError> {
        let n_in = self.n_inputs();
        let n_out = self.n_outputs();
        let shape = ShieldedPoolError::InvalidTransactShape;
        let utxo_roots = self.derived.utxo_roots.get(..n_in).ok_or(shape)?;
        let nullifier_tree_roots = self.derived.nullifier_tree_roots.get(..n_in).ok_or(shape)?;
        let input_owner_pk_hashes = self.derived.input_owner_pk_hashes.get(..n_in).ok_or(shape)?;
        let output_owner_pk_hashes = self
            .derived
            .output_owner_pk_hashes
            .get(..n_out)
            .ok_or(shape)?;

        let p256_message_hash = if self.is_p256() {
            sha256(self.ix.private_tx_hash)?
        } else {
            [0u8; 32]
        };

        let public_spl_asset_pubkey = match self.derived.spl_mint {
            Some(mint) => hash_field(&mint)?,
            None => [0u8; 32],
        };

        let chain = [
            self.nullifier_chain()?,
            self.output_chain()?,
            hash_chain(utxo_roots)?,
            hash_chain(nullifier_tree_roots)?,
            *self.ix.private_tx_hash,
            hash_field(&p256_message_hash)?,
            self.derived.external_data_hash,
            amount_field(self.ix.public_sol_amount),
            amount_field(self.ix.public_spl_amount),
            public_spl_asset_pubkey,
            self.derived.program_id_hashchain,
            self.derived.payer_pubkey_hash,
            [0u8; 32],
            [0u8; 32],
            hash_chain(input_owner_pk_hashes)?,
            hash_chain(output_owner_pk_hashes)?,
            self.derived.p256_signing_pk_field,
        ];
        hash_chain(&chain)
    }

    fn nullifier_chain(&self) -> Result<[u8; 32], ProgramError> {
        let mut iter = self.ix.inputs.iter();
        let Some(first) = iter.next() else {
            return Ok([0u8; 32]);
        };
        let mut acc = first.nullifier_hash;
        for input in iter {
            acc = poseidon2(&acc, &input.nullifier_hash)?;
        }
        Ok(acc)
    }

    fn output_chain(&self) -> Result<[u8; 32], ProgramError> {
        let mut iter = self.ix.output_utxo_hashes.iter();
        let Some(first) = iter.next() else {
            return Ok([0u8; 32]);
        };
        let mut acc = *first;
        for utxo_hash in iter {
            acc = poseidon2(&acc, utxo_hash)?;
        }
        Ok(acc)
    }
}

fn amount_field(amount: Option<i64>) -> [u8; 32] {
    let limbs = Fr::from(amount.unwrap_or(0)).into_bigint().0;
    let mut out = [0u8; 32];
    for (i, limb) in limbs.iter().enumerate() {
        let start = (limbs.len() - 1 - i) * 8;
        out[start..start + 8].copy_from_slice(&limb.to_be_bytes());
    }
    out
}

const PROOF_ERR: ShieldedPoolError = ShieldedPoolError::TransactProofVerificationFailed;

fn poseidon2(a: &[u8; 32], b: &[u8; 32]) -> Result<[u8; 32], ProgramError> {
    verifier::poseidon2(a, b, PROOF_ERR)
}

fn sha256(value: &[u8; 32]) -> Result<[u8; 32], ProgramError> {
    Sha256::hash(value).map_err(|_| PROOF_ERR.into())
}

fn hash_field(value: &[u8; 32]) -> Result<[u8; 32], ProgramError> {
    verifier::hash_field(value, PROOF_ERR)
}

fn hash_chain(items: &[[u8; 32]]) -> Result<[u8; 32], ProgramError> {
    verifier::hash_chain(items, PROOF_ERR)
}

fn select_verifying_key(
    n_inputs: usize,
    n_outputs: usize,
    is_p256: bool,
) -> Result<&'static Groth16Verifyingkey<'static>, ProgramError> {
    match (n_inputs, n_outputs, is_p256) {
        (2, 3, false) => Ok(&transfer_confidential_2_3::VERIFYINGKEY),
        (2, 3, true) => Ok(&transfer_p256_confidential_2_3::VERIFYINGKEY),
        _ => Err(ShieldedPoolError::InvalidTransactShape.into()),
    }
}
