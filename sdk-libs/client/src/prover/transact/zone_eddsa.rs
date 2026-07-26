//! High-level builder for the eddsa-rail zone-transfer proof. This is the
//! ed25519-only (Solana) rail bound to a zone program: a faithful clone of the
//! confidential eddsa [`TransferProver`](super::eddsa::TransferProver) that drops
//! the confidential output-owner appendix and binds the zone program like
//! [`ZoneAuthorityProver`](crate::prover::zone_authority::ZoneAuthorityProver).
//!
//! Unlike the zone-authority variant, owners are NOT anonymous here: the input
//! owner pk_field chain stays in the public-input preimage so SPP can route the
//! per-input signer check. This matches the Go `Confidential=false,
//! ZoneAuthority=false` case in
//! `prover/server/prover-test/spp/protocol/public_inputs.go`: the 12-element base
//! chain, then a tail of the P256 message and `input_owner_pk_hashes`, EXCLUDING
//! the output-owner chain.

use num_bigint::BigUint;
use solana_address::Address;
use zolana_hasher::{hash_chain::create_hash_chain_from_slice, primitives::hash_bytes};
use zolana_transaction::{
    instructions::transact::{PrivateTxHash, PublicMovements},
    utxo::program_id_proof_input_hash,
    ExternalData, SppProofOutputUtxo,
};

use crate::{
    error::ClientError,
    prover::{
        field::be,
        resolve_shape,
        transact::assembly::{assemble_inputs, assemble_outputs, OwnerMode, TransferSpendInput},
        Shape, TransferInputs,
    },
};

/// Zone-bound transfer over the ed25519-only rail. Outputs are anonymous
/// (`SppProofOutputUtxo` with `owner_tag` set and `owner_address: None`); inputs carry
/// their owner pk_field into the public-input chain like a normal transfer.
pub struct ZoneTransferProver {
    pub inputs: Vec<TransferSpendInput>,
    pub outputs: Vec<SppProofOutputUtxo>,
    pub external_data: ExternalData,
    pub public_movements: PublicMovements,
    pub payer_pubkey_hash: [u8; 32],
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
        resolve_shape(self.shape, self.inputs.len(), self.outputs.len())?;

        let assembled_inputs = assemble_inputs(&self.inputs, &OwnerMode::ConfidentialEddsa)?;
        let assembled_outputs = assemble_outputs(&self.outputs)?;
        let external_data_hash = self.external_data.hash()?;
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

        // Zone eddsa-rail public-input layout (Confidential=false,
        // ZoneAuthority=false in public_inputs.go): the 12-element base, then the
        // tail of the P256 message and create_hash_chain_from_slice(
        // input_owner_pk_hashes), with NO confidential appendix (no output-owner
        // chain). hash_bytes(&[0;32]) == Poseidon(0, 0), matching the circuit's
        // zeroed P256 message on the eddsa rail.
        let slots = self.public_movements.interleaved();
        let mut elements = Vec::with_capacity(10 + slots.len());
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
            zone_program_id,
            self.payer_pubkey_hash,
            super::assembly::bool_field(self.allow_dummy_inputs),
            hash_bytes(&[0u8; 32])?,
            create_hash_chain_from_slice(&assembled_inputs.input_owner_pk_hashes)?,
        ]);
        let public_input = create_hash_chain_from_slice(&elements)?;

        let inputs = TransferInputs {
            inputs: assembled_inputs.inputs,
            outputs: assembled_outputs.outputs,
            external_data_hash: be(&external_data_hash),
            private_tx_hash: be(&private_tx),
            public_assets: self.public_movements.assets.map(|asset| be(&asset)),
            public_amounts: self.public_movements.amounts.map(|amount| be(&amount)),
            zone_program_id: be(&zone_program_id),
            payer_pubkey_hash: be(&self.payer_pubkey_hash),
            allow_dummy_inputs: BigUint::from(u8::from(self.allow_dummy_inputs)),
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
