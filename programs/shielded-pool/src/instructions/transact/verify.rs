use ark_bn254::Fr;
use ark_ff::PrimeField;
use arrayvec::ArrayVec as RefArrayVec;
use light_program_profiler::profile;
use pinocchio::{error::ProgramError, AccountView, ProgramResult};
use tinyvec::ArrayVec;
use zolana_account_checks::checks::check_signer;
use zolana_hasher::{
    hash_chain::{create_hash_chain_from_slice, create_hash_chain_from_slice_ref},
    primitives::hash_bytes,
};
use zolana_interface::{
    error::ShieldedPoolError,
    instruction::instruction_data::transact::{ResolvedOutput, TransactIxDataRef},
    N_PUBLIC_SLOTS,
};

use crate::instructions::{hash::solana_pk_hash, verifier};

pub const MAX_INPUTS: usize = 5;

pub const MAX_OUTPUTS: usize = 8;

#[derive(Default, Debug)]
pub struct TransactProofInputs {
    pub utxo_roots: [[u8; 32]; MAX_INPUTS],
    pub nullifier_tree_roots: [[u8; 32]; MAX_INPUTS],
    pub input_owner_pk_hashes: [[u8; 32]; MAX_INPUTS],
    pub output_owner_pk_hashes: [[u8; 32]; MAX_OUTPUTS],
    pub external_data_hash: [u8; 32],
    pub public_slot_assets: [[u8; 32]; N_PUBLIC_SLOTS],
    pub public_slot_amounts: [i128; N_PUBLIC_SLOTS],
    pub zone_program_id: [u8; 32],
    pub payer_pubkey_hash: [u8; 32],
    pub allow_dummy_inputs: [u8; 32],
}

impl TransactProofInputs {
    // Assign the EdDSA signer-derived owner public inputs.
    #[profile]
    pub(crate) fn check_input_signers(
        &mut self,
        accounts: &[AccountView],
        ix: &TransactIxDataRef<'_>,
    ) -> Result<(), ProgramError> {
        for (i, input) in ix.inputs.iter().enumerate() {
            let account = accounts
                .get(usize::from(input.eddsa_signer_index))
                .ok_or(ProgramError::NotEnoughAccountKeys)?;
            check_signer(account)?;
            // TODO: use a hash cache.
            let pk_hash = solana_pk_hash(account.address().as_array())?;
            *self
                .input_owner_pk_hashes
                .get_mut(i)
                .ok_or(ShieldedPoolError::InvalidTransactShape)? = pk_hash;
        }
        Ok(())
    }

    #[profile]
    pub(crate) fn fill_output_owner_pk_hashes(
        &mut self,
        resolved_outputs: &[ResolvedOutput],
    ) -> Result<(), ProgramError> {
        for (slot, output) in self
            .output_owner_pk_hashes
            .iter_mut()
            .zip(resolved_outputs.iter())
        {
            // TODO: use a hash cache.
            *slot = hash_bytes(&output.owner_tag)?; // TODO: check whether we can compute hashes offchain
        }
        Ok(())
    }
}

pub struct TransactProof<'a> {
    ix: &'a TransactIxDataRef<'a>,
    // Borrowed, not owned: `TransactProofInputs` is ~1 KB of fixed arrays. Holding
    // it by value would copy it onto the caller's stack frame (on top of the
    // owner's copy) and overflow the SBF 4 KB frame limit, so the verifier reads it
    // through a reference instead.
    derived: &'a TransactProofInputs,
}

impl<'a> TransactProof<'a> {
    pub fn new(ix: &'a TransactIxDataRef<'a>, derived: &'a TransactProofInputs) -> Self {
        Self { ix, derived }
    }

    /// The processor validates the selector against the dispatched instruction
    /// before account parsing. The validated selector is then the source of truth
    /// for the public-input layout and verifying key.
    #[inline(never)]
    pub fn verify(&self) -> ProgramResult {
        let public_input_hash = self.public_input_hash()?;
        let verifying_key = self
            .ix
            .circuit
            .verifying_key()
            .ok_or(ShieldedPoolError::InvalidTransactShape)?;
        let encoding_err = ShieldedPoolError::InvalidTransactProofEncoding;
        let verify_err = ShieldedPoolError::TransactProofVerificationFailed;
        let proof_data = &self.ix.proof;
        let proof = verifier::CompressedGroth16Proof {
            a: &proof_data.a,
            b: &proof_data.b,
            c: &proof_data.c,
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
        usize::from(self.ix.circuit.num_inputs())
    }

    fn n_outputs(&self) -> usize {
        usize::from(self.ix.circuit.num_outputs())
    }

    fn n_public_asset_slots(&self) -> usize {
        usize::from(self.ix.circuit.num_public_asset_slots())
    }

    #[inline(never)]
    fn public_input_hash(&self) -> Result<[u8; 32], ProgramError> {
        let n_in = self.n_inputs();
        let n_out = self.n_outputs();
        let n_public_asset_slots = self.n_public_asset_slots();
        let shape = ShieldedPoolError::InvalidTransactShape;
        let utxo_roots = self.derived.utxo_roots.get(..n_in).ok_or(shape)?;
        let nullifier_tree_roots = self.derived.nullifier_tree_roots.get(..n_in).ok_or(shape)?;
        let input_owner_pk_hashes = self
            .derived
            .input_owner_pk_hashes
            .get(..n_in)
            .ok_or(shape)?;
        let output_owner_pk_hashes = self
            .derived
            .output_owner_pk_hashes
            .get(..n_out)
            .ok_or(shape)?;
        let public_slot_assets = self
            .derived
            .public_slot_assets
            .get(..n_public_asset_slots)
            .ok_or(shape)?;
        let public_slot_amounts = self
            .derived
            .public_slot_amounts
            .get(..n_public_asset_slots)
            .ok_or(shape)?;

        let nullifier_chain = {
            let mut nullifiers: RefArrayVec<&[u8; 32], MAX_INPUTS> = RefArrayVec::new();
            for input in &self.ix.inputs {
                nullifiers
                    .try_push(&input.nullifier_hash)
                    .map_err(|_| ShieldedPoolError::InvalidTransactShape)?;
            }
            create_hash_chain_from_slice_ref(nullifiers.as_slice())?
        };
        let output_chain = {
            let mut utxo_hashes: RefArrayVec<&[u8; 32], MAX_OUTPUTS> = RefArrayVec::new();
            for output in &self.ix.outputs {
                utxo_hashes
                    .try_push(output.utxo_hash)
                    .map_err(|_| ShieldedPoolError::InvalidTransactShape)?;
            }
            create_hash_chain_from_slice_ref(utxo_hashes.as_slice())?
        };
        let mut fields: ArrayVec<[[u8; 32]; 20]> = ArrayVec::new();
        fields.extend_from_slice(&[
            nullifier_chain,
            output_chain,
            create_hash_chain_from_slice(utxo_roots)?,
            create_hash_chain_from_slice(nullifier_tree_roots)?,
            *self.ix.private_tx_hash,
            self.derived.external_data_hash,
        ]);
        for (asset, amount) in public_slot_assets.iter().zip(public_slot_amounts.iter()) {
            fields.push(*asset);
            fields.push(amount_field(*amount)?);
        }
        fields.extend_from_slice(&[
            self.derived.zone_program_id,
            self.derived.payer_pubkey_hash,
            self.derived.allow_dummy_inputs,
            hash_bytes(&[0u8; 32])?,
        ]);
        if self.ix.circuit.requires_input_signatures() {
            fields.push(create_hash_chain_from_slice(input_owner_pk_hashes)?);
        }
        if self.ix.circuit.binds_output_owners() {
            fields.push(create_hash_chain_from_slice(output_owner_pk_hashes)?);
        }
        create_hash_chain_from_slice(fields.as_slice()).map_err(Into::into)
    }
}

fn amount_field(amount: i128) -> Result<[u8; 32], ProgramError> {
    let magnitude = u64::try_from(amount.unsigned_abs())
        .map_err(|_| ShieldedPoolError::PublicAssetAmountOverflow)?;
    let value = Fr::from(magnitude);
    let limbs = if amount.is_negative() {
        (-value).into_bigint().0
    } else {
        value.into_bigint().0
    };
    let mut out = [0u8; 32];
    for (target, limb) in out.chunks_exact_mut(8).rev().zip(limbs.iter()) {
        target.copy_from_slice(&limb.to_be_bytes());
    }
    Ok(out)
}
