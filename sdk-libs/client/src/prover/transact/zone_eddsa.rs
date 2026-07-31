//! High-level builder for the eddsa-rail zone-transfer proof. This is the
//! ed25519-only (Solana) confidential rail bound to a zone program. It binds
//! the public signer transcript and binds the zone program
//! like [`ZoneAuthorityProver`](crate::prover::zone_authority::ZoneAuthorityProver).
//!
//! Unlike the zone-authority variant, input owners are privately matched
//! against the public Solana signer set. Output owner hashes remain private.

use num_bigint::BigUint;
use solana_address::Address;
use zolana_transaction::{
    instructions::transact::{PrivateTxHash, PublicTransfers},
    utxo::program_id_proof_input_hash,
    ExternalData, SppProofOutputUtxo,
};

use crate::{
    error::ClientError,
    prover::{
        field::be,
        resolve_shape,
        transact::assembly::{
            assemble_inputs, assemble_outputs, confidential_marked_output_owner_pk_hashes,
            OwnerMode, PublicInputs, TransferSpendInput,
        },
        Shape, TransferInputs,
    },
};

/// Confidential zone-bound transfer over the ed25519-only rail.
pub struct ZoneTransferProver {
    pub inputs: Vec<TransferSpendInput>,
    pub outputs: Vec<SppProofOutputUtxo>,
    pub external_data: ExternalData,
    pub public_transfers: PublicTransfers,
    pub signer_pk_hashes: Vec<[u8; 32]>,
    pub allow_dummy_inputs: bool,
    /// The zone program; bound to the public `zone_program_id` and to each
    /// non-dummy UTXO's zone field by the circuit.
    pub zone_program_id: Option<Address>,
    pub shape: Option<Shape>,
}

#[derive(Debug, Clone)]
pub struct ZoneTransferProofResult {
    pub inputs: TransferInputs,
    pub public_input_hash: [u8; 32],
    pub nullifiers: Vec<[u8; 32]>,
    pub output_hashes: Vec<[u8; 32]>,
    pub private_tx_hash: [u8; 32],
    pub input_root_indices: Vec<(u16, u16)>,
}

impl ZoneTransferProver {
    pub fn build(self) -> Result<ZoneTransferProofResult, ClientError> {
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
        let published_output_owner_pk_hashes =
            confidential_marked_output_owner_pk_hashes(&self.external_data)?;
        let private_tx = PrivateTxHash::new(
            &assembled_inputs.input_hashes,
            &assembled_outputs.private_tx_output_hashes,
            &external_data_hash,
        )
        .hash()?;

        // Bind the zone program: zone_program_id is the zone's pk_field. The UTXOs
        // themselves carry zone_program_id; the circuit binds each non-dummy UTXO's
        // zone field to this public input.
        let zone_program_id = program_id_proof_input_hash(&self.zone_program_id)?;

        let public_input = PublicInputs {
            nullifiers: &assembled_inputs.nullifiers,
            output_hashes: &assembled_outputs.output_hashes,
            utxo_roots: &assembled_inputs.utxo_roots,
            nullifier_tree_roots: &assembled_inputs.nullifier_tree_roots,
            private_tx: &private_tx,
            external_data_hash: &external_data_hash,
            public_transfers: &self.public_transfers,
            zone_program_id: &zone_program_id,
            allow_dummy_inputs: &super::assembly::bool_field(self.allow_dummy_inputs),
            signer_pk_hashes: &self.signer_pk_hashes,
            output_owner_pk_hashes: Some(&published_output_owner_pk_hashes),
        }
        .hash()?;

        let inputs = TransferInputs {
            inputs: assembled_inputs.inputs,
            outputs: assembled_outputs.outputs,
            external_data_hash: be(&external_data_hash),
            private_tx_hash: be(&private_tx),
            public_assets: self.public_transfers.assets.map(|asset| be(&asset)),
            public_amounts: self.public_transfers.amounts.map(|amount| be(&amount)),
            zone_program_id: be(&zone_program_id),
            signer_pk_hashes: self.signer_pk_hashes.iter().map(be).collect(),
            allow_dummy_inputs: BigUint::from(u8::from(self.allow_dummy_inputs)),
            published_output_owner_pk_hashes: published_output_owner_pk_hashes
                .iter()
                .map(be)
                .collect(),
            public_input_hash: be(&public_input),
        };

        Ok(ZoneTransferProofResult {
            inputs,
            public_input_hash: public_input,
            nullifiers: assembled_inputs.nullifiers,
            output_hashes: assembled_outputs.output_hashes,
            private_tx_hash: private_tx,
            input_root_indices: assembled_inputs.root_indices,
        })
    }
}
