use ark_bn254::Fr;
use ark_ff::PrimeField;
use groth16_solana::{
    decompression::{decompress_g1, decompress_g2},
    groth16::{Groth16Verifier, Groth16Verifyingkey},
};
use light_hasher::{Hasher, Poseidon, Sha256};
use pinocchio::{error::ProgramError, ProgramResult};
use zolana_interface::{
    instruction::instruction_data::transact::TransactIxDataRef,
    verifying_keys::{transfer_2_3, transfer_p256_2_3},
};

use zolana_interface::error::ShieldedPoolError;

pub const MAX_INPUTS: usize = 5;

pub const P256_OWNED_SIGNER: u8 = 255;

#[derive(Default, Debug)]
pub struct TransactProofInputs {
    pub utxo_roots: [[u8; 32]; MAX_INPUTS],
    pub nullifier_tree_roots: [[u8; 32]; MAX_INPUTS],
    pub solana_owner_pk_hashes: [[u8; 32]; MAX_INPUTS],
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
        let verifying_key =
            select_verifying_key(self.n_inputs(), self.n_outputs(), self.is_p256())?;
        verify_groth16(self.ix.proof, public_input_hash, verifying_key)
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
        let shape = ShieldedPoolError::InvalidTransactShape;
        let utxo_roots = self.derived.utxo_roots.get(..n_in).ok_or(shape)?;
        let nullifier_tree_roots = self.derived.nullifier_tree_roots.get(..n_in).ok_or(shape)?;
        let solana_owner_pk_hashes = self
            .derived
            .solana_owner_pk_hashes
            .get(..n_in)
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
            hash_chain(solana_owner_pk_hashes)?,
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

fn poseidon2(a: &[u8; 32], b: &[u8; 32]) -> Result<[u8; 32], ProgramError> {
    Poseidon::hashv(&[a.as_slice(), b.as_slice()])
        .map_err(|_| ShieldedPoolError::TransactProofVerificationFailed.into())
}

fn sha256(value: &[u8; 32]) -> Result<[u8; 32], ProgramError> {
    Sha256::hash(value).map_err(|_| ShieldedPoolError::TransactProofVerificationFailed.into())
}

fn hash_field(value: &[u8; 32]) -> Result<[u8; 32], ProgramError> {
    let (high_bytes, low_bytes) = value.split_at(16);
    poseidon2(&right_align_16(low_bytes), &right_align_16(high_bytes))
}

fn right_align_16(bytes: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[16..].copy_from_slice(bytes);
    out
}

fn hash_chain(items: &[[u8; 32]]) -> Result<[u8; 32], ProgramError> {
    let mut iter = items.iter();
    let Some(first) = iter.next() else {
        return Ok([0u8; 32]);
    };
    let mut acc = *first;
    for item in iter {
        acc = poseidon2(&acc, item)?;
    }
    Ok(acc)
}

fn select_verifying_key(
    n_inputs: usize,
    n_outputs: usize,
    is_p256: bool,
) -> Result<&'static Groth16Verifyingkey<'static>, ProgramError> {
    match (n_inputs, n_outputs, is_p256) {
        (2, 3, false) => Ok(&transfer_2_3::VERIFYINGKEY),
        (2, 3, true) => Ok(&transfer_p256_2_3::VERIFYINGKEY),
        _ => Err(ShieldedPoolError::InvalidTransactShape.into()),
    }
}

fn verify_groth16(
    proof: &[u8; 192],
    public_input_hash: [u8; 32],
    verifying_key: &Groth16Verifyingkey,
) -> ProgramResult {
    let proof_a = decompress_g1(chunk::<32>(proof, 0)?).map_err(proof_encoding)?;
    let proof_b = decompress_g2(chunk::<64>(proof, 32)?).map_err(proof_encoding)?;
    let proof_c = decompress_g1(chunk::<32>(proof, 96)?).map_err(proof_encoding)?;
    let public_inputs = [public_input_hash];

    if verifying_key.vk_commitment_g2.is_some() {
        let commitment = decompress_g1(chunk::<32>(proof, 128)?).map_err(proof_encoding)?;
        let commitment_pok = decompress_g1(chunk::<32>(proof, 160)?).map_err(proof_encoding)?;
        let mut verifier = Groth16Verifier::new_with_commitment(
            &proof_a,
            &proof_b,
            &proof_c,
            &commitment,
            &commitment_pok,
            &public_inputs,
            verifying_key,
        )
        .map_err(verification_failed)?;
        verifier.verify().map_err(verification_failed)?;
    } else {
        let mut verifier =
            Groth16Verifier::new(&proof_a, &proof_b, &proof_c, &public_inputs, verifying_key)
                .map_err(verification_failed)?;
        verifier.verify().map_err(verification_failed)?;
    }
    Ok(())
}

fn chunk<const N: usize>(data: &[u8], start: usize) -> Result<&[u8; N], ProgramError> {
    data.get(start..start + N)
        .ok_or(ShieldedPoolError::InvalidTransactProofEncoding)?
        .try_into()
        .map_err(|_| ShieldedPoolError::InvalidTransactProofEncoding.into())
}

fn proof_encoding<E>(_: E) -> ProgramError {
    ShieldedPoolError::InvalidTransactProofEncoding.into()
}

fn verification_failed<E>(_: E) -> ProgramError {
    ShieldedPoolError::TransactProofVerificationFailed.into()
}
