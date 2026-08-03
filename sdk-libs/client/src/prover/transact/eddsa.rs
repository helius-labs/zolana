use num_bigint::BigUint;
use zolana_transaction::{
    instructions::transact::{PrivateTxHash, PublicTransfers},
    ExternalData, SppProofOutputUtxo,
};

use crate::{
    error::ClientError,
    prover::{
        field::be,
        resolve_shape,
        transact::assembly::{
            assemble_inputs, assemble_outputs, OwnerMode, PublicInputs, TransferSpendInput,
        },
        Shape, TransferInputs,
    },
};

pub struct TransferProver {
    pub inputs: Vec<TransferSpendInput>,
    pub outputs: Vec<SppProofOutputUtxo>,
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
    pub input_root_indices: Vec<(u16, u16)>,
}

impl TransferProver {
    pub fn build(self) -> Result<TransferProofResult, ClientError> {
        let shape = resolve_shape(self.shape, self.inputs.len(), self.outputs.len())?;
        if self.signer_pk_hashes.len() != shape.n_inputs() + 1 {
            return Err(ClientError::WitnessInputCountMismatch {
                got: self.signer_pk_hashes.len(),
                expected: shape.n_inputs() + 1,
            });
        }
        let assembled_inputs = assemble_inputs(&self.inputs, &OwnerMode::ConfidentialEddsa)?;
        let assembled_outputs = assemble_outputs(&self.outputs)?;
        let external_data_hash = self.external_data.hash()?;
        let private_tx = PrivateTxHash::new(
            &assembled_inputs.input_hashes,
            &assembled_outputs.private_tx_output_hashes,
            &external_data_hash,
        )
        .hash()?;
        let public_input = PublicInputs {
            nullifiers: &assembled_inputs.nullifiers,
            output_hashes: &assembled_outputs.output_hashes,
            utxo_roots: &assembled_inputs.utxo_roots,
            nullifier_tree_roots: &assembled_inputs.nullifier_tree_roots,
            private_tx: &private_tx,
            external_data_hash: &external_data_hash,
            public_transfers: &self.public_transfers,
            ring_program_id: &[0u8; 32],
            allow_dummy_inputs: &super::assembly::bool_field(self.allow_dummy_inputs),
            signer_pk_hashes: &self.signer_pk_hashes,
            output_owner_pk_hashes: Some(&assembled_outputs.output_owner_pk_hashes),
        }
        .hash()?;

        let inputs = TransferInputs {
            inputs: assembled_inputs.inputs,
            outputs: assembled_outputs.outputs,
            external_data_hash: be(&external_data_hash),
            private_tx_hash: be(&private_tx),
            public_assets: self.public_transfers.assets.map(|asset| be(&asset)),
            public_amounts: self.public_transfers.amounts.map(|amount| be(&amount)),
            ring_program_id: BigUint::ZERO,
            signer_pk_hashes: self.signer_pk_hashes.iter().map(be).collect(),
            allow_dummy_inputs: BigUint::from(u8::from(self.allow_dummy_inputs)),
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
            input_root_indices: assembled_inputs.root_indices,
        })
    }
}
