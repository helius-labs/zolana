//! Anonymous custom-ring transfer proof builder. The hidden Ed25519 owner signs
//! the transaction message digest, and the proof verifies that signature.

use num_bigint::BigUint;
use serde_json::{Map, Value};
use solana_address::Address;
use zeroize::Zeroizing;
use zolana_hasher::primitives::hash_bytes;
use zolana_interface::instruction::instruction_data::transact::TreeContext;
use zolana_keypair::SigningKey;
use zolana_transaction::{
    instructions::transact::{transact_message_hash, PublicTransfers},
    utxo::program_id_proof_input_hash,
    ExternalData, SppProofOutputUtxo,
};

use crate::{
    error::ClientError,
    prover::{
        cache::CacheSelection,
        client::{Delivery, ProveRequest},
        field::be,
        json::to_json_ring,
        proving_key::ExpectedProvingKey,
        transact::assembly::{
            assemble_transaction, confidential_marked_output_owner_pk_hashes, validate_shape,
            AssembledTransaction, OwnerMode, PublicInputs, TransferInputUtxo,
        },
        Shape, TransferInputs, TreeSlotFields,
    },
};

pub struct AnonymousRingEd25519Prover<'a> {
    pub inputs: Vec<TransferInputUtxo>,
    pub outputs: Vec<SppProofOutputUtxo>,
    /// The transaction's private random root seed. See
    /// [`TransferProver::blinding_seed`](crate::prover::TransferProver).
    pub blinding_seed: [u8; 32],
    /// Raw id of the tree every output is appended to.
    pub output_tree_id: u16,
    pub external_data: ExternalData,
    pub public_transfers: PublicTransfers,
    pub signer_pk_hashes: Vec<[u8; 32]>,
    pub allow_dummy_inputs: bool,
    /// The hidden owner. Every input it owns carries the zero owner tag.
    pub owner: &'a SigningKey,
    pub ring_program_id: Option<Address>,
    pub shape: Shape,
}

#[derive(Debug, Clone)]
pub struct AnonymousRingEd25519ProofResult {
    pub inputs: AnonymousEd25519TransferInputs,
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

/// The Solana-only proof inputs plus the hidden owner's key, its signature and
/// the signed digest. The rail publishes no output owner.
#[derive(Debug, Clone)]
pub struct AnonymousEd25519TransferInputs {
    pub transfer: TransferInputs,
    pub owner_public_key: [u8; 32],
    pub owner_signature: [u8; 64],
    pub message_digest: [u8; 32],
}

impl AnonymousRingEd25519Prover<'_> {
    pub fn build(self) -> Result<AnonymousRingEd25519ProofResult, ClientError> {
        let shape = self.shape;
        validate_shape(shape, self.inputs.len(), self.outputs.len())?;
        if self.signer_pk_hashes.len() != shape.signer_width() {
            return Err(ClientError::WitnessInputCountMismatch {
                got: self.signer_pk_hashes.len(),
                expected: shape.signer_width(),
            });
        }
        for (index, output) in self.outputs.iter().enumerate() {
            if !output.is_dummy()
                && self
                    .ring_program_id
                    .is_none_or(|ring| output.ring_program_id != Some(ring))
            {
                return Err(ClientError::AnonymousOutputNotInRing { index });
            }
        }
        let owner = self.owner.pubkey();
        let owner_public_key = owner.as_ed25519()?;

        let cache = CacheSelection::derive(
            &self.inputs,
            &self.outputs,
            Default::default(),
            &self.external_data,
        )?;
        let AssembledTransaction {
            inputs: assembled_inputs,
            outputs: assembled_outputs,
            external_data_hash,
            private_tx_hash: private_tx,
            input_flags,
        } = assemble_transaction(
            &self.inputs,
            &self.outputs,
            &self.blinding_seed,
            self.output_tree_id,
            &cache.external_data_hash,
            &OwnerMode::AnonymousEd25519(owner),
            self.allow_dummy_inputs,
        )?;
        // The circuit commits zero owners, so a marked output fails the proof here
        // rather than on chain.
        let published_output_owner_pk_hashes =
            confidential_marked_output_owner_pk_hashes(&self.external_data, self.outputs.len())?;
        let message_digest = transact_message_hash(&private_tx, &external_data_hash);
        let owner_signature = self.owner.sign_message(&message_digest)?;

        let ring_program_id = program_id_proof_input_hash(&self.ring_program_id)?;
        let public_input = PublicInputs {
            nullifiers: &assembled_inputs.nullifiers,
            output_hashes: &assembled_outputs.output_hashes,
            tree_slots: &assembled_inputs.tree_slots,
            output_tree_id: self.output_tree_id,
            private_tx: &private_tx,
            external_data_hash: &external_data_hash,
            public_transfers: &self.public_transfers,
            ring_program_id: &ring_program_id,
            input_flags: &input_flags,
            signer_pk_hashes: &self.signer_pk_hashes,
            output_owner_pk_hashes: Some(&published_output_owner_pk_hashes),
            cached_inputs: cache.public_fields,
        }
        .hash_with_after_private_tx(&[hash_bytes(&message_digest)?, [0u8; 32]])?;

        let transfer = TransferInputs {
            inputs: assembled_inputs.inputs,
            outputs: assembled_outputs.outputs,
            tree_slots: TreeSlotFields::encode_all(&assembled_inputs.tree_slots),
            output_tree_id: BigUint::from(self.output_tree_id),
            blinding_seed: be(&self.blinding_seed),
            external_data_hash: be(&external_data_hash),
            private_tx_hash: be(&private_tx),
            public_assets: self.public_transfers.assets.map(|asset| be(&asset)),
            public_amounts: self.public_transfers.amounts.map(|amount| be(&amount)),
            ring_program_id: be(&ring_program_id),
            signer_pk_hashes: self.signer_pk_hashes.iter().map(be).collect(),
            input_flags: be(&input_flags),
            published_output_owner_pk_hashes: Vec::new(),
            cache: cache.proof_inputs,
            public_input_hash: be(&public_input),
        };

        Ok(AnonymousRingEd25519ProofResult {
            inputs: AnonymousEd25519TransferInputs {
                transfer,
                owner_public_key,
                owner_signature,
                message_digest,
            },
            public_input_hash: public_input,
            nullifiers: assembled_inputs.nullifiers,
            output_hashes: assembled_outputs.output_hashes,
            private_tx_hash: private_tx,
            tree_contexts: assembled_inputs.tree_contexts,
            input_tree_indexes: assembled_inputs.input_tree_indexes,
        })
    }
}

impl ProveRequest for AnonymousEd25519TransferInputs {
    /// The Solana-only wire form with the circuit type and the owner fields of
    /// the prover's `AnonymousEd25519TransferParametersJSON`.
    fn body(&self) -> Result<Zeroizing<String>, ClientError> {
        let mut body: Map<String, Value> = serde_json::from_str(&to_json_ring(&self.transfer)?)
            .expect("the transfer request is a JSON object");
        body.insert(
            "circuitType".to_string(),
            Value::String("transfer-ed25519-ring".to_string()),
        );
        body.extend(owner_fields(
            &self.owner_public_key,
            &self.owner_signature,
            &self.message_digest,
        ));
        Ok(Zeroizing::new(Value::Object(body).to_string()))
    }

    fn proving_key(&self) -> Result<ExpectedProvingKey, ClientError> {
        ExpectedProvingKey::transfer_anonymous_ring_ed25519(
            self.transfer.inputs.len(),
            self.transfer.outputs.len(),
        )
    }

    fn delivery(&self) -> Delivery {
        Delivery::InResponse
    }
}

/// Encodes the same owner authorization for complete and indexed witnesses.
pub(crate) fn owner_fields(
    public_key: &[u8; 32],
    signature: &[u8; 64],
    digest: &[u8; 32],
) -> Map<String, Value> {
    let (high, low) = digest.split_at(16);
    [
        ("ownerPublicKey", hex::encode(public_key)),
        ("ownerSignature", hex::encode(signature)),
        ("messageHashLow", hex::encode(low)),
        ("messageHashHigh", hex::encode(high)),
    ]
    .into_iter()
    .map(|(name, value)| (name.to_string(), Value::String(format!("0x{value}"))))
    .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The body splits the digest into the prover's limbs and carries every key
    /// of the committed Go request.
    #[test]
    fn body_carries_the_prover_owner_fields() {
        let inputs = AnonymousEd25519TransferInputs {
            transfer: TransferInputs {
                inputs: Vec::new(),
                outputs: Vec::new(),
                tree_slots: Default::default(),
                output_tree_id: BigUint::ZERO,
                blinding_seed: BigUint::from(1u8),
                external_data_hash: BigUint::ZERO,
                private_tx_hash: BigUint::ZERO,
                public_assets: Default::default(),
                public_amounts: Default::default(),
                ring_program_id: BigUint::ZERO,
                signer_pk_hashes: Vec::new(),
                input_flags: BigUint::ZERO,
                published_output_owner_pk_hashes: Vec::new(),
                cache: Default::default(),
                public_input_hash: BigUint::ZERO,
            },
            owner_public_key: [1u8; 32],
            owner_signature: [2u8; 64],
            message_digest: core::array::from_fn(|index| index as u8),
        };
        let body: Value = serde_json::from_str(&inputs.body().unwrap()).unwrap();
        assert_eq!(body["circuitType"], "transfer-ed25519-ring");
        assert_eq!(body["ownerPublicKey"], format!("0x{}", "01".repeat(32)));
        assert_eq!(body["ownerSignature"], format!("0x{}", "02".repeat(64)));
        assert_eq!(
            body["messageHashHigh"],
            "0x000102030405060708090a0b0c0d0e0f"
        );
        assert_eq!(body["messageHashLow"], "0x101112131415161718191a1b1c1d1e1f");
        assert_eq!(
            body["publishedOutputOwnerPkHashes"],
            Value::Array(Vec::new())
        );

        let request: Map<String, Value> = serde_json::from_str(include_str!(
            "../../../../../prover/server/prover/transfer_eddsa_only/testdata/ed25519-ring-2x2.json"
        ))
        .unwrap();
        for key in request.keys() {
            assert!(body.get(key).is_some(), "{key}");
        }
    }
}
