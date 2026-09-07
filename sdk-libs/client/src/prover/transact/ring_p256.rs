//! Custom-ring transfer proof builder with a shared P256 authorization.

use num_bigint::BigUint;
use p256::{
    ecdsa::{signature::hazmat::PrehashVerifier, Signature, VerifyingKey},
    elliptic_curve::sec1::ToEncodedPoint,
};
use solana_address::Address;
use zolana_hasher::primitives::{hash_bytes, p256_owner_identity};
use zolana_keypair::{hash::sha256, Curve};
use zolana_transaction::{
    instructions::transact::{PrivateTxHash, PublicTransfers},
    utxo::{derive_output_blinding_seed, derive_private_tx_blinding, program_id_proof_input_hash},
    ExternalData, P256Signature, SppProofOutputUtxo,
};

use crate::{
    error::ClientError,
    prover::{
        field::be,
        resolve_shape,
        transact::assembly::{
            assemble_inputs, assemble_outputs, bool_field,
            confidential_marked_output_owner_pk_hashes, validate_output_blindings, OwnerMode,
            PublicInputs, TransferSpendInput,
        },
        Shape, TransferP256Inputs, TreeSlotFields,
    },
};

pub struct RingTransferP256Prover {
    pub inputs: Vec<TransferSpendInput>,
    pub outputs: Vec<SppProofOutputUtxo>,
    /// The transaction's single private random value. See
    /// [`TransferProver::tx_secret`](crate::prover::TransferProver).
    pub tx_secret: [u8; 32],
    /// Raw id of the tree every output is appended to.
    pub output_tree_id: u16,
    pub external_data: ExternalData,
    pub public_transfers: PublicTransfers,
    pub signer_pk_hashes: Vec<[u8; 32]>,
    pub allow_dummy_inputs: bool,
    pub authorization: P256Signature,
    pub ring_program_id: Option<Address>,
    pub shape: Option<Shape>,
}

#[derive(Debug, Clone)]
pub struct RingTransferP256ProofResult {
    pub inputs: TransferP256Inputs,
    pub public_input_hash: [u8; 32],
    pub nullifiers: Vec<[u8; 32]>,
    pub output_hashes: Vec<[u8; 32]>,
    pub private_tx_hash: [u8; 32],
    /// Index into `input_tree`'s UTXO root cache, shared by every input.
    pub utxo_tree_root_index: u16,
    /// Index into `input_tree`'s nullifier root cache, shared by every input.
    pub nullifier_tree_root_index: u16,
    /// Raw P256 x-coordinate carried in `CircuitId::RingP256` when the shared
    /// owner spends a default-ring UTXO. Address slots never set it.
    pub default_owner_tag: Option<[u8; 32]>,
}

impl RingTransferP256Prover {
    pub fn build(self) -> Result<RingTransferP256ProofResult, ClientError> {
        let shape = resolve_shape(self.shape, self.inputs.len(), self.outputs.len())?;
        if self.signer_pk_hashes.len() != shape.n_inputs() + 1 {
            return Err(ClientError::WitnessInputCountMismatch {
                got: self.signer_pk_hashes.len(),
                expected: shape.n_inputs() + 1,
            });
        }

        let assembled_inputs = assemble_inputs(&self.inputs, &OwnerMode::RingP256)?;
        let first_nullifier = assembled_inputs
            .nullifiers
            .first()
            .ok_or(ClientError::NoInputs)?;
        let output_blinding_seed = derive_output_blinding_seed(first_nullifier, &self.tx_secret)?;
        validate_output_blindings(&self.outputs, first_nullifier, &output_blinding_seed)?;
        let assembled_outputs = assemble_outputs(&self.outputs, self.output_tree_id)?;
        let external_data_hash = self.external_data.hash()?;
        let published_output_owner_pk_hashes =
            confidential_marked_output_owner_pk_hashes(&self.external_data)?;
        let private_tx_blinding = derive_private_tx_blinding(first_nullifier, &self.tx_secret)?;
        let private_tx = PrivateTxHash::new(
            &assembled_inputs.input_hashes,
            &assembled_outputs.private_tx_output_hashes,
            &external_data_hash,
            &private_tx_blinding,
        )
        .hash()?;
        let message_digest = sha256(&private_tx);
        validate_authorization(&self.inputs, &self.authorization, &message_digest)?;

        let public_key = self.authorization.pubkey.to_p256()?;
        let point = public_key.to_encoded_point(false);
        let pub_x = coordinate(point.x(), "x")?;
        let pub_y = coordinate(point.y(), "y")?;
        // The shared P256 identity is published only when a default-ring P256
        // UTXO is spent. A ring-bound P256 spend is anonymous, so it may not
        // coexist with a default-ring spend and no published output owner may
        // name the identity while it happens.
        let p256_owner_pk_hash = p256_owner_identity(&pub_x)?;
        let spends = p256_spend_rings(&self.inputs)?;
        if spends.default_ring && spends.bound_ring {
            return Err(ClientError::RingP256MixedDefaultAndRingSpend);
        }
        if spends.bound_ring {
            if let Some(index) = published_output_owner_pk_hashes
                .iter()
                .position(|published| *published == p256_owner_pk_hash)
            {
                return Err(ClientError::RingP256PublishedOwnerLeaksIdentity { index });
            }
        }
        let default_owner_tag = spends.default_ring.then_some(pub_x);
        let default_p256_owner_pk_hash = match default_owner_tag {
            Some(_) => p256_owner_pk_hash,
            None => [0u8; 32],
        };

        let ring_program_id = program_id_proof_input_hash(&self.ring_program_id)?;
        let message_proof_input_hash = hash_bytes(&message_digest)?;
        let public_input = PublicInputs {
            nullifiers: &assembled_inputs.nullifiers,
            output_hashes: &assembled_outputs.output_hashes,
            tree_slots: &assembled_inputs.tree_slots,
            output_tree_id: self.output_tree_id,
            private_tx: &private_tx,
            external_data_hash: &external_data_hash,
            public_transfers: &self.public_transfers,
            ring_program_id: &ring_program_id,
            allow_dummy_inputs: &bool_field(self.allow_dummy_inputs),
            signer_pk_hashes: &self.signer_pk_hashes,
            output_owner_pk_hashes: Some(&published_output_owner_pk_hashes),
        }
        .hash_with_after_private_tx(&[message_proof_input_hash, default_p256_owner_pk_hash])?;

        let inputs = TransferP256Inputs {
            inputs: assembled_inputs.inputs,
            outputs: assembled_outputs.outputs,
            tree_slots: TreeSlotFields::encode_all(&assembled_inputs.tree_slots),
            output_tree_id: BigUint::from(self.output_tree_id),
            tx_secret: be(&self.tx_secret),
            external_data_hash: be(&external_data_hash),
            private_tx_hash: be(&private_tx),
            p256_pub_x: be(&pub_x),
            p256_pub_y: be(&pub_y),
            p256_sig_r: be(&self.authorization.sig_r),
            p256_sig_s: be(&self.authorization.sig_s),
            p256_message_hash_low: BigUint::from_bytes_be(&message_digest[16..]),
            p256_message_hash_high: BigUint::from_bytes_be(&message_digest[..16]),
            default_p256_owner_pk_hash: be(&default_p256_owner_pk_hash),
            public_assets: self.public_transfers.assets.map(|asset| be(&asset)),
            public_amounts: self.public_transfers.amounts.map(|amount| be(&amount)),
            ring_program_id: be(&ring_program_id),
            signer_pk_hashes: self.signer_pk_hashes.iter().map(be).collect(),
            allow_dummy_inputs: BigUint::from(u8::from(self.allow_dummy_inputs)),
            published_output_owner_pk_hashes: published_output_owner_pk_hashes
                .iter()
                .map(be)
                .collect(),
            public_input_hash: be(&public_input),
        };

        Ok(RingTransferP256ProofResult {
            inputs,
            public_input_hash: public_input,
            nullifiers: assembled_inputs.nullifiers,
            output_hashes: assembled_outputs.output_hashes,
            private_tx_hash: private_tx,
            utxo_tree_root_index: assembled_inputs.utxo_tree_root_index,
            nullifier_tree_root_index: assembled_inputs.nullifier_tree_root_index,
            default_owner_tag,
        })
    }
}

/// Which rings the proof's spent P256 UTXOs belong to. Only spends count: an
/// address slot creates nothing that names an owner, so it neither publishes
/// the shared identity nor forbids a ring spend.
struct P256SpendRings {
    default_ring: bool,
    bound_ring: bool,
}

fn p256_spend_rings(inputs: &[TransferSpendInput]) -> Result<P256SpendRings, ClientError> {
    let mut rings = P256SpendRings {
        default_ring: false,
        bound_ring: false,
    };
    for spend in inputs {
        if spend.proof.is_none() || spend.utxo.owner.curve()? != Curve::P256 {
            continue;
        }
        if spend.utxo.ring_program_id.is_some() {
            rings.bound_ring = true;
        } else {
            rings.default_ring = true;
        }
    }
    Ok(rings)
}

fn validate_authorization(
    inputs: &[TransferSpendInput],
    authorization: &P256Signature,
    message_digest: &[u8; 32],
) -> Result<(), ClientError> {
    let mut found_p256 = false;
    for (index, spend) in inputs.iter().enumerate() {
        if spend.proof.is_none() {
            continue;
        }
        if spend.utxo.owner.curve()? != Curve::P256 {
            continue;
        }
        found_p256 = true;
        if spend.utxo.owner.as_p256()? != authorization.pubkey {
            return Err(ClientError::P256AuthorizationOwnerMismatch { index });
        }
    }
    if !found_p256 {
        return Err(ClientError::P256ProofWithoutP256Input);
    }

    let mut signature_bytes = [0u8; 64];
    signature_bytes[..32].copy_from_slice(&authorization.sig_r);
    signature_bytes[32..].copy_from_slice(&authorization.sig_s);
    let signature = Signature::from_slice(&signature_bytes)
        .map_err(|e| ClientError::InvalidP256Authorization(e.to_string()))?;
    let verifying_key = VerifyingKey::from_sec1_bytes(authorization.pubkey.as_bytes())
        .map_err(|e| ClientError::InvalidP256Authorization(e.to_string()))?;
    verifying_key
        .verify_prehash(message_digest, &signature)
        .map_err(|e| ClientError::InvalidP256Authorization(e.to_string()))
}

fn coordinate(
    coordinate: Option<&p256::elliptic_curve::FieldBytes<p256::NistP256>>,
    name: &str,
) -> Result<[u8; 32], ClientError> {
    let coordinate = coordinate.ok_or_else(|| {
        ClientError::InvalidP256Authorization(format!("missing {name} coordinate"))
    })?;
    let mut out = [0u8; 32];
    out.copy_from_slice(coordinate);
    Ok(out)
}
