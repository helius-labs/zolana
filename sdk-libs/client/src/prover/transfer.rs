use num_bigint::BigUint;
use zolana_transaction::{transaction::private_tx_hash, ExternalData, OutputUtxo};

use crate::{
    error::ClientError,
    private_transaction::field::be,
    prover::{
        shape::{resolve_shape, Shape},
        transfer_p256::{
            assemble_inputs, assemble_outputs, PublicAmounts, PublicInputs, TransferSpendInput,
        },
        TransferInputs,
    },
};

pub struct TransferProver {
    pub inputs: Vec<TransferSpendInput>,
    pub outputs: Vec<OutputUtxo>,
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
        let assembled_inputs = assemble_inputs(&self.inputs, false)?;
        let assembled_outputs = assemble_outputs(&self.outputs)?;
        let external_data_hash = self.external_data.hash()?;
        let private_tx = private_tx_hash(
            &assembled_inputs.input_hashes,
            &assembled_outputs.private_tx_output_hashes,
            &external_data_hash,
        )?;
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
            payer_pubkey_hash: &self.payer_pubkey_hash,
            solana_owner_pk_hashes: &assembled_inputs.solana_owner_pk_hashes,
        }
        .hash()?;

        let inputs = TransferInputs {
            inputs: assembled_inputs.inputs,
            outputs: assembled_outputs.outputs,
            external_data_hash: be(&external_data_hash),
            private_tx_hash: be(&private_tx),
            public_sol_amount: be(&self.public_amounts.sol),
            public_spl_amount: be(&self.public_amounts.spl),
            public_spl_asset_pubkey: be(&self.public_amounts.asset),
            program_id_hashchain: BigUint::ZERO,
            payer_pubkey_hash: be(&self.payer_pubkey_hash),
            data_hash: BigUint::ZERO,
            zone_data_hash: BigUint::ZERO,
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
