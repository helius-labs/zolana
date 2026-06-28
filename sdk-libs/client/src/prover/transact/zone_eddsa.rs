//! High-level builder for the eddsa-rail zone-transfer proof. This is the
//! ed25519-only (Solana) rail bound to a zone program: a faithful clone of the
//! confidential eddsa [`TransferProver`](super::eddsa::TransferProver) that drops
//! the confidential appendix (output owner chain + `p256_signing_pk_field`) and
//! binds the zone program like
//! [`ZoneAuthorityProver`](crate::prover::zone_authority::ZoneAuthorityProver).
//!
//! Unlike the zone-authority variant, owners are NOT anonymous here: the input
//! owner pk_field chain stays in the public-input preimage so SPP can route the
//! per-input signer check. This matches the Go `Confidential=false,
//! ZoneAuthority=false` case in
//! `prover/server/prover-test/spp/protocol/public_inputs.go`: the 14-element base
//! chain INCLUDING `input_owner_pk_hashes`, EXCLUDING the output-owner chain and
//! `p256_signing_pk_field`.

use solana_address::Address;
use zolana_keypair::hash::hash_field;
use zolana_transaction::{
    instructions::transact::{no_address_hashes, private_tx_hash},
    utxo::program_id_field,
    ExternalData, OutputUtxo,
};

use crate::{
    error::ClientError,
    prover::{
        field::{be, hash_chain},
        shape::{resolve_shape, Shape},
        transact::p256_and_eddsa::{
            assemble_inputs, assemble_outputs, OwnerMode, PublicAmounts, TransferSpendInput,
        },
        TransferInputs,
    },
};

/// Zone-bound transfer over the ed25519-only rail. Outputs are anonymous
/// (`OutputUtxo` with `owner_tag` set and `owner_address: None`); inputs carry
/// their owner pk_field into the public-input chain like a normal transfer.
pub struct ZoneTransferProver {
    pub inputs: Vec<TransferSpendInput>,
    pub outputs: Vec<OutputUtxo>,
    pub external_data: ExternalData,
    pub public_amounts: PublicAmounts,
    pub payer_pubkey_hash: [u8; 32],
    /// The CPI program bound to the public `program_id`; `None` leaves it 0.
    pub program_id: Option<Address>,
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
        resolve_shape(self.shape, self.inputs.len(), self.outputs.len())?;

        let assembled_inputs = assemble_inputs(&self.inputs, &OwnerMode::ConfidentialEddsa)?;
        let assembled_outputs = assemble_outputs(&self.outputs)?;
        let external_data_hash = self.external_data.hash()?;
        let private_tx = private_tx_hash(
            &assembled_inputs.input_hashes,
            &assembled_outputs.private_tx_output_hashes,
            &no_address_hashes(assembled_inputs.input_hashes.len()),
            &external_data_hash,
        )?;

        // Bind the zone program: program_id is 0 (no ZK program), zone_program_id is
        // the zone's pk_field. The UTXOs themselves carry zone_program_id; the circuit
        // binds each non-dummy UTXO's zone field to this public input.
        let program_id = program_id_field(&self.program_id)?;
        let zone_program_id = program_id_field(&self.zone_program_id)?;

        // Zone eddsa-rail public-input layout: the 14-element base chain
        // (Confidential=false, ZoneAuthority=false in public_inputs.go), i.e. the 13
        // base elements PLUS hash_chain(input_owner_pk_hashes), with NO confidential
        // appendix (no output-owner chain, no p256_signing_pk_field). hash_field(&[0;32])
        // == Poseidon(0, 0), matching the circuit's zeroed P256MessageHash element on
        // the eddsa rail.
        let public_input = hash_chain(&[
            hash_chain(&assembled_inputs.nullifiers)?,
            hash_chain(&assembled_outputs.output_hashes)?,
            hash_chain(&assembled_inputs.utxo_roots)?,
            hash_chain(&assembled_inputs.nullifier_tree_roots)?,
            private_tx,
            hash_field(&[0u8; 32])?,
            external_data_hash,
            self.public_amounts.sol,
            self.public_amounts.spl,
            self.public_amounts.asset,
            program_id,
            zone_program_id,
            self.payer_pubkey_hash,
            hash_chain(&assembled_inputs.input_owner_pk_hashes)?,
        ])?;

        let inputs = TransferInputs {
            inputs: assembled_inputs.inputs,
            outputs: assembled_outputs.outputs,
            external_data_hash: be(&external_data_hash),
            private_tx_hash: be(&private_tx),
            public_sol_amount: be(&self.public_amounts.sol),
            public_spl_amount: be(&self.public_amounts.spl),
            public_spl_asset_pubkey: be(&self.public_amounts.asset),
            program_id: be(&program_id),
            zone_program_id: be(&zone_program_id),
            payer_pubkey_hash: be(&self.payer_pubkey_hash),
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
