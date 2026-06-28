//! High-level builder for the zone P256 transfer proof (`zone_transact`, P256
//! rail). It mirrors the confidential [`TransferP256Prover`] verbatim -- same
//! input/output assembly and same P256 signature witness -- but binds the zone
//! program and keeps the anonymous zone public-input layout: input owners stay
//! private (the per-input pk_field is the `0` sentinel for P256 owners), there is
//! no output-owner chain, and the shared `p256_signing_pk_field` is not folded
//! into the hash.

use num_bigint::BigUint;
use solana_address::Address;
use zolana_keypair::{
    hash::{hash_field, sha256, split_be_128},
    PublicKey,
};
use zolana_transaction::{
    instructions::transact::private_tx_hash, utxo::program_id_field, ExternalData, OutputUtxo,
};

use crate::{
    error::ClientError,
    prover::{
        field::{be, hash_chain},
        shape::{resolve_shape, Shape},
        transact::p256_and_eddsa::{
            assemble_inputs, assemble_outputs, OwnerMode, P256Owner, PublicAmounts,
            TransferSpendInput,
        },
        TransferP256Inputs,
    },
};

/// Zone P256 state transition over zone-owned UTXOs, authorized by the shared
/// P256 owner signature. Like [`TransferP256Prover`] the proof carries the P256
/// signature witness, but ownership stays anonymous: the zone program is bound to
/// the public `zone_program_id` and to each non-dummy UTXO's zone field, while the
/// per-input owner pk_fields are kept private (P256 owners contribute the `0`
/// sentinel via [`OwnerMode::Zone`]).
pub struct ZoneTransferP256Prover {
    pub inputs: Vec<TransferSpendInput>,
    pub outputs: Vec<OutputUtxo>,
    pub external_data: ExternalData,
    pub public_amounts: PublicAmounts,
    pub payer_pubkey_hash: [u8; 32],
    pub p256_owner: P256Owner,
    /// The zone program; bound to the public `zone_program_id` and to each
    /// non-dummy UTXO's zone field by the circuit.
    pub zone_program_id: Option<Address>,
    pub shape: Option<Shape>,
}

#[derive(Debug, Clone)]
pub struct ZoneTransferP256ProofResult {
    pub inputs: TransferP256Inputs,
    pub public_input_hash: [u8; 32],
    pub nullifiers: Vec<[u8; 32]>,
    pub output_hashes: Vec<[u8; 32]>,
    pub private_tx_hash: [u8; 32],
    pub input_root_indices: Vec<(u16, u16)>,
    /// The shared P256 owner `pk_field` (big-endian) exposed as the `Transact`
    /// instruction's `p256_signing_pk_field`. Unlike the confidential rail it is
    /// NOT folded into the zone public-input hash, but it is still carried in the
    /// witness so the circuit can route ownership by equality.
    pub p256_signing_pk_field: [u8; 32],
}

impl ZoneTransferP256Prover {
    pub fn build(self) -> Result<ZoneTransferP256ProofResult, ClientError> {
        resolve_shape(self.shape, self.inputs.len(), self.outputs.len())?;
        // The shared P256 signing key's pk_field: the value every P256-owned input
        // exposes as its in-circuit P256 pk_field so the circuit routes ownership by
        // equality. Carried in the witness only; not folded into the zone hash.
        let p256_signing_pk_field =
            PublicKey::from_p256(&self.p256_owner.pubkey).owner_pk_field()?;
        let assembled_inputs = assemble_inputs(&self.inputs, &OwnerMode::Zone)?;
        let assembled_outputs = assemble_outputs(&self.outputs)?;
        let external_data_hash = self.external_data.hash()?;
        let private_tx = private_tx_hash(
            &assembled_inputs.input_hashes,
            &assembled_outputs.private_tx_output_hashes,
            &external_data_hash,
        )?;
        let p256_message_hash = sha256(&private_tx);
        let signature = self.p256_owner.witness()?;
        let (p256_message_low, p256_message_high) = split_be_128(&p256_message_hash);

        // Bind the zone program: program_id is 0 (no ZK program), zone_program_id is
        // the zone's pk_field. The UTXOs themselves carry zone_program_id; the circuit
        // binds each non-dummy UTXO's zone field to this public input.
        let program_id = [0u8; 32];
        let zone_program_id = program_id_field(&self.zone_program_id)?;

        // Zone P256 public-input layout: the 14-element base chain (input owner
        // pk_fields committed, but P256 owners contribute the 0 sentinel so identities
        // stay private), with the real hash_field(p256_message_hash) at the
        // p256-message position. No output-owner chain and no p256_signing_pk_field.
        // Mirrors PublicInputHash with ZoneAuthority=false, Confidential=false in
        // prover/server/prover-test/spp/protocol/public_inputs.go.
        let public_input = hash_chain(&[
            hash_chain(&assembled_inputs.nullifiers)?,
            hash_chain(&assembled_outputs.output_hashes)?,
            hash_chain(&assembled_inputs.utxo_roots)?,
            hash_chain(&assembled_inputs.nullifier_tree_roots)?,
            private_tx,
            hash_field(&p256_message_hash)?,
            external_data_hash,
            self.public_amounts.sol,
            self.public_amounts.spl,
            self.public_amounts.asset,
            program_id,
            zone_program_id,
            self.payer_pubkey_hash,
            hash_chain(&assembled_inputs.input_owner_pk_hashes)?,
        ])?;

        let inputs = TransferP256Inputs {
            inputs: assembled_inputs.inputs,
            outputs: assembled_outputs.outputs,
            external_data_hash: be(&external_data_hash),
            p256_pub_x: be(&signature.pub_x),
            p256_pub_y: be(&signature.pub_y),
            p256_sig_r: be(&signature.sig_r),
            p256_sig_s: be(&signature.sig_s),
            private_tx_hash: be(&private_tx),
            p256_message_hash_low: be(&p256_message_low),
            p256_message_hash_high: be(&p256_message_high),
            public_sol_amount: be(&self.public_amounts.sol),
            public_spl_amount: be(&self.public_amounts.spl),
            public_spl_asset_pubkey: be(&self.public_amounts.asset),
            program_id: BigUint::ZERO,
            zone_program_id: be(&zone_program_id),
            payer_pubkey_hash: be(&self.payer_pubkey_hash),
            p256_signing_pk_field: be(&p256_signing_pk_field),
            public_input_hash: be(&public_input),
        };

        Ok(ZoneTransferP256ProofResult {
            inputs,
            public_input_hash: public_input,
            nullifiers: assembled_inputs.nullifiers,
            output_hashes: assembled_outputs.output_hashes,
            private_tx_hash: private_tx,
            input_root_indices: assembled_inputs.root_indices,
            p256_signing_pk_field,
        })
    }
}
