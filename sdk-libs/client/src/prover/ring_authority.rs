//! High-level builder for the ring-authority proof (`ring_authority_transact`).
//! The ring authority has full control over its ring-owned UTXOs, so owners do not
//! sign: there is no P256 signature and no per-input signer. It reuses the spp
//! transfer input/output assembly verbatim ([`assemble_inputs`]/[`assemble_outputs`])
//! in the pubkey-agnostic [`OwnerMode::RingAuthority`] mode; only the public-input
//! element set differs (input owner pk_fields stay private, no confidential
//! appendix).

use num_bigint::BigUint;
use solana_address::Address;
use zolana_hasher::hash_chain::create_hash_chain_from_slice;
use zolana_transaction::{
    instructions::{
        ring_authority::PreparedRingAuthority,
        transact::{PrivateTxHash, PublicTransfers},
    },
    utxo::program_id_proof_input_hash,
    ExternalData, SppProofOutputUtxo,
};

use crate::{
    error::ClientError,
    prover::{
        field::be,
        resolve_shape,
        transact::{
            assembly::{assemble_inputs, assemble_outputs, OwnerMode, TransferSpendInput},
            witness::{attach_input_proofs, SpendProof},
        },
        Shape, TransferInputs,
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
    /// Transaction-level public data; its `instruction_discriminator` must be
    /// `RING_AUTHORITY_TRANSACT` (tag 17) so `external_data_hash` matches on-chain.
    pub external_data: ExternalData,
    pub private_tx_blinding: [u8; 32],
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
    /// Per-input `(utxo_tree_root_index, nullifier_tree_root_index)`, for the
    /// `ring_authority_transact` instruction data (a later phase).
    pub input_root_indices: Vec<(u16, u16)>,
}

impl RingAuthorityProver {
    pub fn build(self) -> Result<RingAuthorityProofResult, ClientError> {
        resolve_shape(self.shape, self.inputs.len(), self.outputs.len())?;

        let assembled_inputs = assemble_inputs(&self.inputs, &OwnerMode::RingAuthority)?;
        let assembled_outputs = assemble_outputs(&self.outputs)?;
        let external_data_hash = self.external_data.hash()?;
        let private_tx = PrivateTxHash::new(
            &assembled_inputs.input_hashes,
            &assembled_outputs.private_tx_output_hashes,
            &external_data_hash,
            &self.private_tx_blinding,
        )
        .hash()?;

        // Bind the ring program: ring_program_id is the ring's pk_field. The UTXOs
        // themselves carry ring_program_id; the circuit binds each non-dummy UTXO's
        // ring field to this public input.
        let ring_program_id = program_id_proof_input_hash(&self.ring_program_id)?;
        let payer_pk_hash = zolana_hasher::primitives::hash_bytes(self.payer.as_array())?;

        // Ring-authority public-input layout: input owner pk_fields stay private
        // (no owner chain) and there is no confidential appendix.
        let slots = self.public_transfers.interleaved();
        let mut elements = Vec::with_capacity(9 + slots.len());
        elements.extend([
            create_hash_chain_from_slice(&assembled_inputs.nullifiers)?,
            create_hash_chain_from_slice(&assembled_outputs.output_hashes)?,
            create_hash_chain_from_slice(&assembled_inputs.utxo_roots)?,
            create_hash_chain_from_slice(&assembled_inputs.nullifier_tree_roots)?,
            private_tx,
            external_data_hash,
        ]);
        elements.extend(slots);
        elements.extend([
            ring_program_id,
            // The authority signer vector contains only the payer. A one-element
            // right-fold is the element itself.
            payer_pk_hash,
            crate::prover::transact::assembly::bool_field(self.allow_dummy_inputs),
        ]);
        let public_input = create_hash_chain_from_slice(&elements)?;

        let inputs = TransferInputs {
            inputs: assembled_inputs.inputs,
            outputs: assembled_outputs.outputs,
            external_data_hash: be(&external_data_hash),
            private_tx_hash: be(&private_tx),
            private_tx_blinding: be(&self.private_tx_blinding),
            public_assets: self.public_transfers.assets.map(|asset| be(&asset)),
            public_amounts: self.public_transfers.amounts.map(|amount| be(&amount)),
            ring_program_id: be(&ring_program_id),
            signer_pk_hashes: vec![be(&payer_pk_hash)],
            allow_dummy_inputs: BigUint::from(u8::from(self.allow_dummy_inputs)),
            published_output_owner_pk_hashes: Vec::new(),
            public_input_hash: be(&public_input),
        };

        Ok(RingAuthorityProofResult {
            inputs,
            public_input_hash: public_input,
            nullifiers: assembled_inputs.nullifiers,
            output_hashes: assembled_outputs.output_hashes,
            private_tx_hash: private_tx,
            input_root_indices: assembled_inputs.root_indices,
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
            external_data,
            private_tx_blinding:
                zolana_transaction::instructions::transact::new_private_tx_blinding(),
            public_transfers,
            payer,
            allow_dummy_inputs: true,
            ring_program_id,
            shape: Some(shape),
        })
    }
}
