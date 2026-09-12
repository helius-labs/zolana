use num_bigint::BigUint;
use zolana_interface::{
    instruction::instruction_data::transact::TreeContext, tree_slot::pack_input_flags,
};
use zolana_transaction::{
    instructions::transact::{PrivateTxHash, PublicTransfers},
    utxo::{derive_output_blinding_seed, derive_private_tx_blinding},
    ExternalData, SppProofOutputUtxo,
};

use crate::{
    error::ClientError,
    prover::{
        field::be,
        resolve_shape,
        transact::assembly::{
            assemble_inputs, assemble_outputs, validate_output_blindings, OwnerMode, PublicInputs,
            TransferSpendInput,
        },
        Shape, TransferInputs, TreeSlotFields,
    },
};

pub struct TransferProver {
    pub inputs: Vec<TransferSpendInput>,
    pub outputs: Vec<SppProofOutputUtxo>,
    /// The transaction's private random root seed. The output blinding seed
    /// and the private transaction blinding derive from it and the first
    /// nullifier; the circuit repeats both derivations.
    pub blinding_seed: [u8; 32],
    /// Raw id of the tree every output is appended to.
    pub output_tree_id: u16,
    pub external_data: ExternalData,
    pub public_transfers: PublicTransfers,
    pub signer_pk_hashes: Vec<[u8; 32]>,
    pub allow_dummy_inputs: bool,
    pub shape: Option<Shape>,
}

#[derive(Debug, Clone)]
pub struct TransferProofResult {
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

impl TransferProver {
    pub fn build(self) -> Result<TransferProofResult, ClientError> {
        let shape = resolve_shape(self.shape, self.inputs.len(), self.outputs.len())?;
        if self.signer_pk_hashes.len() != shape.signer_width() {
            return Err(ClientError::WitnessInputCountMismatch {
                got: self.signer_pk_hashes.len(),
                expected: shape.signer_width(),
            });
        }
        let assembled_inputs = assemble_inputs(&self.inputs, &OwnerMode::ConfidentialEddsa)?;
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
        let public_input = PublicInputs {
            nullifiers: &assembled_inputs.nullifiers,
            output_hashes: &assembled_outputs.output_hashes,
            tree_slots: &assembled_inputs.tree_slots,
            output_tree_id: self.output_tree_id,
            private_tx: &private_tx,
            external_data_hash: &external_data_hash,
            public_transfers: &self.public_transfers,
            ring_program_id: &[0u8; 32],
            input_flags: &input_flags,
            signer_pk_hashes: &self.signer_pk_hashes,
            output_owner_pk_hashes: Some(&assembled_outputs.output_owner_pk_hashes),
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
            ring_program_id: BigUint::ZERO,
            signer_pk_hashes: self.signer_pk_hashes.iter().map(be).collect(),
            input_flags: be(&input_flags),
            published_output_owner_pk_hashes: assembled_outputs
                .output_owner_pk_hashes
                .iter()
                .map(be)
                .collect(),
            public_input_hash: be(&public_input),
        };

        Ok(TransferProofResult {
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
