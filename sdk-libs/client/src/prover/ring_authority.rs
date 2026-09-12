//! High-level builder for the ring-authority proof (`ring_authority_transact`).
//! The ring authority has full control over its ring-owned UTXOs, so owners do not
//! sign: there is no P256 signature and no per-input signer. It reuses the spp
//! transfer input/output assembly verbatim ([`assemble_inputs`]/[`assemble_outputs`])
//! in the pubkey-agnostic [`OwnerMode::RingAuthority`] mode; only the public-input
//! element set differs (input owner pk_fields stay private, no confidential
//! appendix).

use num_bigint::BigUint;
use solana_address::Address;
use zolana_hasher::primitives::solana_owner_identity;
use zolana_interface::{
    instruction::instruction_data::transact::TreeContext, tree_slot::pack_input_flags,
};
use zolana_transaction::{
    instructions::{
        ring_authority::PreparedRingAuthority,
        transact::{PrivateTxHash, PublicTransfers},
    },
    utxo::{derive_output_blinding_seed, derive_private_tx_blinding, program_id_proof_input_hash},
    ExternalData, SppProofOutputUtxo,
};

use crate::{
    error::ClientError,
    prover::{
        field::be,
        resolve_shape,
        transact::{
            assembly::{
                assemble_inputs, assemble_outputs, validate_output_blindings, OwnerMode,
                PublicInputs, TransferSpendInput,
            },
            witness::{attach_input_proofs, SpendProof},
        },
        Shape, TransferInputs, TreeSlotFields,
    },
    rpc::NonInclusionProof,
};

/// Ring-authority state transition over ring-owned UTXOs. The ring authority is
/// authorized on-chain (the `ring_config` PDA signs); the proof carries no
/// signature. Owners are opaque field elements bound through their nullifier
/// secrets, exactly like the merge circuit, and stay private (anonymous).
pub struct RingAuthorityProver {
    /// Input slots; a `None` proof on [`TransferSpendInput`] is a dummy. Each real
    /// input's `nullifier_key` is supplied by the ring authority.
    pub inputs: Vec<TransferSpendInput>,
    pub outputs: Vec<SppProofOutputUtxo>,
    /// The transaction's private random root seed. See
    /// [`TransferProver::blinding_seed`](crate::prover::TransferProver).
    pub blinding_seed: [u8; 32],
    /// Raw id of the tree every output is appended to.
    pub output_tree_id: u16,
    /// Transaction-level public data; its `instruction_discriminator` must be
    /// `RING_AUTHORITY_TRANSACT` (tag 21) so `external_data_hash` matches on-chain.
    pub external_data: ExternalData,
    pub public_transfers: PublicTransfers,
    pub payer: Address,
    pub allow_dummy_inputs: bool,
    /// The ring program; bound to the public `ring_program_id` and to each
    /// non-dummy UTXO's ring field by the circuit.
    pub ring_program_id: Option<Address>,
    pub shape: Option<Shape>,
}

#[derive(Debug, Clone)]
pub struct RingAuthorityProofResult {
    pub inputs: TransferInputs,
    pub public_input_hash: [u8; 32],
    pub nullifiers: Vec<[u8; 32]>,
    pub output_hashes: Vec<[u8; 32]>,
    pub private_tx_hash: [u8; 32],
    /// One root-index pair per input tree, in the order the tree accounts are
    /// passed. An input selects its pair with its `tree_index`.
    pub tree_contexts: Vec<TreeContext>,
    /// Each input's index into `tree_contexts`, parallel to `nullifiers`.
    pub input_tree_indexes: Vec<u8>,
}

impl RingAuthorityProver {
    pub fn build(self) -> Result<RingAuthorityProofResult, ClientError> {
        resolve_shape(self.shape, self.inputs.len(), self.outputs.len())?;

        let assembled_inputs = assemble_inputs(&self.inputs, &OwnerMode::RingAuthority)?;
        let input_flags = pack_input_flags(
            self.allow_dummy_inputs,
            assembled_inputs.input_tree_indexes.iter().copied(),
        )?;
        let first_nullifier = assembled_inputs
            .nullifiers
            .first()
            .ok_or(ClientError::NoInputs)?;
        let output_blinding_seed =
            derive_output_blinding_seed(first_nullifier, &self.blinding_seed)?;
        validate_output_blindings(&self.outputs, first_nullifier, &output_blinding_seed)?;
        let assembled_outputs = assemble_outputs(&self.outputs, self.output_tree_id)?;
        let external_data_hash = self.external_data.hash()?;
        let private_tx_blinding = derive_private_tx_blinding(first_nullifier, &self.blinding_seed)?;
        let private_tx = PrivateTxHash::new(
            &assembled_inputs.input_hashes,
            &assembled_outputs.private_tx_output_hashes,
            &external_data_hash,
            &private_tx_blinding,
        )
        .hash()?;

        // Bind the ring program: ring_program_id is the ring's pk_field. The UTXOs
        // themselves carry ring_program_id; the circuit binds each non-dummy UTXO's
        // ring field to this public input.
        let ring_program_id = program_id_proof_input_hash(&self.ring_program_id)?;
        let payer_pk_hash = solana_owner_identity(self.payer.as_array())?;

        // Ring-authority public-input layout: input owner pk_fields stay private
        // (no owner chain) and there is no confidential appendix. The authority
        // signer vector holds only the payer, and a one-element right fold is
        // the element itself.
        let signer_pk_hashes = [payer_pk_hash];
        let public_input = PublicInputs {
            nullifiers: &assembled_inputs.nullifiers,
            output_hashes: &assembled_outputs.output_hashes,
            tree_slots: &assembled_inputs.tree_slots,
            output_tree_id: self.output_tree_id,
            private_tx: &private_tx,
            external_data_hash: &external_data_hash,
            public_transfers: &self.public_transfers,
            ring_program_id: &ring_program_id,
            input_flags: &input_flags,
            signer_pk_hashes: &signer_pk_hashes,
            output_owner_pk_hashes: None,
        }
        .hash()?;

        let inputs = TransferInputs {
            inputs: assembled_inputs.inputs,
            outputs: assembled_outputs.outputs,
            tree_slots: TreeSlotFields::encode_all(&assembled_inputs.tree_slots),
            output_tree_id: BigUint::from(self.output_tree_id),
            blinding_seed: be(&self.blinding_seed),
            external_data_hash: be(&external_data_hash),
            private_tx_hash: be(&private_tx),
            public_assets: self.public_transfers.assets.map(|asset| be(&asset)),
            public_amounts: self.public_transfers.amounts.map(|amount| be(&amount)),
            ring_program_id: be(&ring_program_id),
            signer_pk_hashes: vec![be(&payer_pk_hash)],
            input_flags: be(&input_flags),
            published_output_owner_pk_hashes: Vec::new(),
            public_input_hash: be(&public_input),
        };

        Ok(RingAuthorityProofResult {
            inputs,
            public_input_hash: public_input,
            nullifiers: assembled_inputs.nullifiers,
            output_hashes: assembled_outputs.output_hashes,
            private_tx_hash: private_tx,
            tree_contexts: assembled_inputs.tree_contexts,
            input_tree_indexes: assembled_inputs.input_tree_indexes,
        })
    }
}

/// A [`PreparedRingAuthority`] plus the fetched Merkle proofs, ready to fold into a
/// [`RingAuthorityProver`]. Mirrors the merge `MergeWitness` pattern: one
/// [`SpendProof`] per real (non-dummy) input, in input order.
pub struct RingAuthorityWitness {
    pub prepared: PreparedRingAuthority,
    pub proofs: Vec<SpendProof>,
    /// One nullifier non-inclusion proof per dummy input, in dummy-slot order.
    /// Unlike merge, the shared transfer circuit checks non-inclusion for every
    /// slot, including padding.
    pub dummy_nullifier_proofs: Vec<NonInclusionProof>,
}

impl TryFrom<RingAuthorityWitness> for RingAuthorityProver {
    type Error = ClientError;

    fn try_from(witness: RingAuthorityWitness) -> Result<Self, Self::Error> {
        let RingAuthorityWitness {
            prepared,
            proofs,
            dummy_nullifier_proofs,
        } = witness;
        let PreparedRingAuthority {
            inputs,
            outputs,
            blinding_seed,
            output_tree_id,
            public_transfers,
            external_data,
            payer,
            ring_program_id,
            shape,
        } = prepared;

        let spends = attach_input_proofs(inputs, &proofs, &dummy_nullifier_proofs)?;

        Ok(RingAuthorityProver {
            inputs: spends,
            outputs,
            blinding_seed,
            output_tree_id,
            external_data,
            public_transfers,
            payer,
            allow_dummy_inputs: true,
            ring_program_id,
            shape: Some(shape),
        })
    }
}
