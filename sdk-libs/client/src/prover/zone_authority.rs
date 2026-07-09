//! High-level builder for the zone-authority proof (`zone_authority_transact`).
//! The zone authority has full control over its zone-owned UTXOs, so owners do not
//! sign: there is no P256 signature and no per-input signer. It reuses the spp
//! transfer input/output assembly verbatim ([`assemble_inputs`]/[`assemble_outputs`])
//! in the pubkey-agnostic [`OwnerMode::ZoneAuthority`] mode; only the public-input
//! element set differs (input owner pk_fields stay private, no confidential
//! appendix).

use rings_keypair::hash::hash_field;
use rings_transaction::{
    instructions::{
        transact::{no_address_hashes, private_tx_hash},
        zone_authority::PreparedZoneAuthority,
    },
    utxo::program_id_field,
    ExternalData, OutputUtxo,
};
use solana_address::Address;

use crate::{
    error::ClientError,
    prover::{
        field::{be, hash_chain},
        shape::{resolve_shape, Shape},
        transact::{
            p256_and_eddsa::{
                assemble_inputs, assemble_outputs, OwnerMode, PublicAmounts, TransferSpendInput,
            },
            witness::SpendProof,
        },
        TransferInputs,
    },
};

/// Zone-authority state transition over zone-owned UTXOs. The zone authority is
/// authorized on-chain (the `zone_config` PDA signs); the proof carries no
/// signature. Owners are opaque field elements bound through their nullifier
/// secrets, exactly like the merge circuit, and stay private (anonymous).
pub struct ZoneAuthorityProver {
    /// Input slots; a `None` proof on [`TransferSpendInput`] is a dummy. Each real
    /// input's `nullifier_key` is supplied by the zone authority.
    pub inputs: Vec<TransferSpendInput>,
    pub outputs: Vec<OutputUtxo>,
    /// Transaction-level public data; its `instruction_discriminator` must be
    /// `ZONE_AUTHORITY_TRANSACT` (Tag 3) so `external_data_hash` matches on-chain.
    pub external_data: ExternalData,
    pub public_amounts: PublicAmounts,
    pub payer_pubkey_hash: [u8; 32],
    /// The zone program; bound to the public `zone_program_id` and to each
    /// non-dummy UTXO's zone field by the circuit.
    pub zone_program_id: Option<Address>,
    pub shape: Option<Shape>,
}

#[derive(Debug, Clone)]
pub struct ZoneAuthorityProofResult {
    pub inputs: TransferInputs,
    pub public_input_hash: [u8; 32],
    pub nullifiers: Vec<[u8; 32]>,
    pub output_hashes: Vec<[u8; 32]>,
    pub private_tx_hash: [u8; 32],
    /// Per-input `(utxo_tree_root_index, nullifier_tree_root_index)`, for the
    /// `zone_authority_transact` instruction data (a later phase).
    pub input_root_indices: Vec<(u16, u16)>,
}

impl ZoneAuthorityProver {
    pub fn build(self) -> Result<ZoneAuthorityProofResult, ClientError> {
        resolve_shape(self.shape, self.inputs.len(), self.outputs.len())?;

        let assembled_inputs = assemble_inputs(&self.inputs, &OwnerMode::ZoneAuthority)?;
        let assembled_outputs = assemble_outputs(&self.outputs)?;
        let external_data_hash = self.external_data.hash()?;
        let private_tx = private_tx_hash(
            &assembled_inputs.input_hashes,
            &assembled_outputs.private_tx_output_hashes,
            &no_address_hashes(assembled_inputs.input_hashes.len()),
            &external_data_hash,
        )?;

        // Bind the zone program: zone_program_id is the zone's pk_field. The UTXOs
        // themselves carry zone_program_id; the circuit binds each non-dummy UTXO's
        // zone field to this public input.
        let zone_program_id = program_id_field(&self.zone_program_id)?;

        // Zone-authority public-input layout: the 12 base elements, with input owner
        // pk_fields kept private (no owner chain) and no confidential appendix.
        // Mirrors NewTransferZoneAuthorityCircuit's publicInputHash. hash_field(&[0;32])
        // == Poseidon(0, 0), matching the circuit's zeroed P256MessageHash element.
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
            zone_program_id,
            self.payer_pubkey_hash,
        ])?;

        let inputs = TransferInputs {
            inputs: assembled_inputs.inputs,
            outputs: assembled_outputs.outputs,
            external_data_hash: be(&external_data_hash),
            private_tx_hash: be(&private_tx),
            public_sol_amount: be(&self.public_amounts.sol),
            public_spl_amount: be(&self.public_amounts.spl),
            public_spl_asset_pubkey: be(&self.public_amounts.asset),
            zone_program_id: be(&zone_program_id),
            payer_pubkey_hash: be(&self.payer_pubkey_hash),
            public_input_hash: be(&public_input),
        };

        Ok(ZoneAuthorityProofResult {
            inputs,
            public_input_hash: public_input,
            nullifiers: assembled_inputs.nullifiers,
            output_hashes: assembled_outputs.output_hashes,
            private_tx_hash: private_tx,
            input_root_indices: assembled_inputs.root_indices,
        })
    }
}

/// A [`PreparedZoneAuthority`] plus the fetched Merkle proofs, ready to fold into a
/// [`ZoneAuthorityProver`]. Mirrors the merge `MergeWitness` pattern: one
/// [`SpendProof`] per real (non-dummy) input, in input order.
pub struct ZoneAuthorityWitness {
    pub prepared: PreparedZoneAuthority,
    pub proofs: Vec<SpendProof>,
}

impl TryFrom<ZoneAuthorityWitness> for ZoneAuthorityProver {
    type Error = ClientError;

    fn try_from(witness: ZoneAuthorityWitness) -> Result<Self, Self::Error> {
        let ZoneAuthorityWitness { prepared, proofs } = witness;
        let PreparedZoneAuthority {
            inputs,
            outputs,
            public_amounts,
            external_data,
            payer_pubkey_hash,
            zone_program_id,
            shape,
        } = prepared;

        // Attach a proof to each real input; a dummy (zero owner) is proofless and
        // mirrors the first real input's roots during assembly.
        let mut spends = Vec::with_capacity(inputs.len());
        let mut real_index = 0;
        for spend in inputs {
            let proof = if spend.utxo.owner.is_zero() {
                None
            } else {
                let proof = proofs
                    .get(real_index)
                    .ok_or(ClientError::MissingInputMerkleProof { index: real_index })?
                    .clone();
                real_index += 1;
                Some(proof)
            };
            spends.push(TransferSpendInput {
                utxo: spend.utxo,
                nullifier_key: spend.nullifier_key,
                data_hash: spend.data_hash,
                zone_data_hash: spend.zone_data_hash,
                proof,
            });
        }

        Ok(ZoneAuthorityProver {
            inputs: spends,
            outputs,
            external_data,
            public_amounts: PublicAmounts {
                sol: public_amounts.sol,
                spl: public_amounts.spl,
                asset: public_amounts.asset,
            },
            payer_pubkey_hash,
            zone_program_id,
            shape: Some(Shape::new(shape.n_inputs, shape.n_outputs)),
        })
    }
}
