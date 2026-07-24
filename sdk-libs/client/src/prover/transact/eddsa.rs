use num_bigint::BigUint;
use zolana_transaction::{instructions::transact::PrivateTxHash, ExternalData, SppProofOutputUtxo};

use crate::{
    error::ClientError,
    prover::{
        field::be,
        resolve_shape,
        transact::p256_and_eddsa::{
            assemble_inputs, assemble_outputs, OwnerMode, PublicAmounts, PublicInputs,
            TransferSpendInput,
        },
        Shape, TransferInputs,
    },
};

pub struct TransferProver {
    pub inputs: Vec<TransferSpendInput>,
    pub outputs: Vec<SppProofOutputUtxo>,
    pub external_data: ExternalData,
    pub public_amounts: PublicAmounts,
    pub payer_pubkey_hash: [u8; 32],
    pub shape: Option<Shape>,
}

#[derive(Debug, Clone)]
pub struct TransferProofResult {
    pub inputs: TransferInputs,
    pub public_input_hash: [u8; 32],
    pub nullifiers: Vec<[u8; 32]>,
    pub output_hashes: Vec<[u8; 32]>,
    pub private_tx_hash: [u8; 32],
    pub input_root_indices: Vec<(u16, u16)>,
}

impl TransferProver {
    pub fn build(self) -> Result<TransferProofResult, ClientError> {
        resolve_shape(self.shape, self.inputs.len(), self.outputs.len())?;
        // The eddsa rail has no P256 owner, so the shared signing pk_field is 0 even
        // in the confidential variant; only the output owner tags are bound.
        let p256_signing_pk_field = [0u8; 32];
        let assembled_inputs = assemble_inputs(&self.inputs, &OwnerMode::ConfidentialEddsa)?;
        let assembled_outputs = assemble_outputs(&self.outputs)?;
        let external_data_hash = self.external_data.hash()?;
        let private_tx = PrivateTxHash::new(
            &assembled_inputs.input_hashes,
            &assembled_outputs.private_tx_output_hashes,
            &external_data_hash,
        )
        .hash()?;
        let p256_message_hash = [0u8; 32];
        let public_input = PublicInputs {
            nullifiers: &assembled_inputs.nullifiers,
            output_hashes: &assembled_outputs.output_hashes,
            utxo_roots: &assembled_inputs.utxo_roots,
            nullifier_tree_roots: &assembled_inputs.nullifier_tree_roots,
            private_tx: &private_tx,
            p256_message_hash: &p256_message_hash,
            external_data_hash: &external_data_hash,
            public_amounts: &self.public_amounts,
            zone_program_id: &[0u8; 32],
            payer_pubkey_hash: &self.payer_pubkey_hash,
            input_owner_pk_hashes: &assembled_inputs.input_owner_pk_hashes,
            output_owner_pk_hashes: &assembled_outputs.output_owner_pk_hashes,
            p256_signing_pk_field: &p256_signing_pk_field,
        }
        .hash()?;

        let inputs = TransferInputs {
            inputs: assembled_inputs.inputs,
            outputs: assembled_outputs.outputs,
            external_data_hash: be(&external_data_hash),
            private_tx_hash: be(&private_tx),
            public_assets: self.public_amounts.assets.map(|asset| be(&asset)),
            public_amounts: self.public_amounts.amounts.map(|amount| be(&amount)),
            zone_program_id: BigUint::ZERO,
            payer_pubkey_hash: be(&self.payer_pubkey_hash),
            public_input_hash: be(&public_input),
        };

        Ok(TransferProofResult {
            inputs,
            public_input_hash: public_input,
            nullifiers: assembled_inputs.nullifiers,
            output_hashes: assembled_outputs.output_hashes,
            private_tx_hash: private_tx,
            input_root_indices: assembled_inputs.root_indices,
        })
    }
}
