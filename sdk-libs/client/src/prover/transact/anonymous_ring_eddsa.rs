//! Anonymous custom-ring transfer proof builder. The hidden Ed25519 owner signs
//! the transaction message digest, and the proof verifies that signature.

use num_bigint::BigUint;
use serde_json::{Map, Value};
use solana_address::Address;
use spr_hasher::primitives::{hash_bytes, solana_owner_identity};
use spr_interface::instruction::instruction_data::transact::TreeContext;
use spr_keypair::{PublicKey, SigningKey};
use spr_transaction::{
    instructions::transact::{transact_message_hash, PublicTransfers, SppProofInputs},
    utxo::program_id_proof_input_hash,
    ExternalData, SppProofOutputUtxo,
};
use zeroize::Zeroizing;

use crate::{
    error::ClientError,
    prover::{
        cache::CacheSelection,
        client::{Delivery, ProveRequest},
        field::be,
        indexed::hex_field,
        json::to_json_ring,
        proving_key::ExpectedProvingKey,
        transact::assembly::{
            assemble_transaction, confidential_marked_output_owner_pk_hashes, validate_shape,
            AssembledTransaction, OwnerMode, PublicInputs, TransferInputUtxo,
        },
        Shape, TransferInputs, TreeSlotFields,
    },
};

pub struct AnonymousRingEddsaProver<'a> {
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
pub struct AnonymousRingEddsaProofResult {
    pub inputs: AnonymousEddsaTransferInputs,
    pub public_input_hash: [u8; 32],
    pub nullifiers: Vec<[u8; 32]>,
    pub output_hashes: Vec<[u8; 32]>,
    pub private_tx_hash: [u8; 32],
    /// One root-index pair per input tree, in the order the tree accounts are
    /// passed. An input selects its pair with its `tree_index`.
    pub tree_contexts: Vec<TreeContext>,
    /// Each input's index into `tree_contexts`, parallel to `nullifiers`.
    pub input_tree_indexes: Vec<u8>,
    /// Raw Ed25519 key carried in `CircuitId::AnonymousRingEddsa` when the hidden
    /// owner spends a default-ring UTXO. Address slots never set it.
    pub default_owner_tag: Option<[u8; 32]>,
}

/// The Solana-only proof inputs plus the hidden owner's authorization.
#[derive(Debug, Clone)]
pub struct AnonymousEddsaTransferInputs {
    pub transfer: TransferInputs,
    pub authorization: AnonymousEddsaAuthorization,
}

#[derive(Debug, Clone)]
pub struct AnonymousEddsaAuthorization {
    pub owner_public_key: [u8; 32],
    pub owner_signature: [u8; 64],
    pub message_digest: [u8; 32],
    /// Program-derived public hash of the hidden owner when it spends a
    /// default-ring UTXO, zero otherwise.
    pub default_owner_pk_hash: [u8; 32],
}

impl AnonymousRingEddsaProver<'_> {
    pub fn assemble(self) -> Result<AnonymousRingEddsaProofResult, ClientError> {
        let shape = self.shape;
        validate_shape(shape, self.inputs.len(), self.outputs.len())?;
        if self.signer_pk_hashes.len() != shape.signer_width() {
            return Err(ClientError::WitnessInputCountMismatch {
                got: self.signer_pk_hashes.len(),
                expected: shape.signer_width(),
            });
        }

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
            &OwnerMode::AnonymousEddsa(self.owner.pubkey()),
            self.allow_dummy_inputs,
        )?;
        let published_output_owner_pk_hashes =
            confidential_marked_output_owner_pk_hashes(&self.external_data, self.outputs.len())?;
        let PreparedAnonymousAuthorization {
            authorization,
            default_owner_tag,
        } = AnonymousAuthorizationPreparation {
            inputs: &self.inputs,
            owner: self.owner,
            private_tx: &private_tx,
            external_data_hash: &external_data_hash,
            published_owners: &published_output_owner_pk_hashes,
        }
        .prepare()?;

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
        .hash_with_after_private_tx(&authorization.public_fields()?)?;

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
            published_output_owner_pk_hashes: published_output_owner_pk_hashes
                .iter()
                .map(be)
                .collect(),
            cache: cache.proof_inputs,
            public_input_hash: be(&public_input),
        };

        Ok(AnonymousRingEddsaProofResult {
            inputs: AnonymousEddsaTransferInputs {
                transfer,
                authorization,
            },
            public_input_hash: public_input,
            nullifiers: assembled_inputs.nullifiers,
            output_hashes: assembled_outputs.output_hashes,
            private_tx_hash: private_tx,
            tree_contexts: assembled_inputs.tree_contexts,
            input_tree_indexes: assembled_inputs.input_tree_indexes,
            default_owner_tag,
        })
    }
}

/// Signer identities without the hidden owner, which authorizes only inside the proof.
pub(crate) fn anonymous_signer_pk_hashes(
    transaction: &SppProofInputs,
    owner: &PublicKey,
) -> Result<Vec<[u8; 32]>, ClientError> {
    let width = transaction.check_shape()?.signer_width();
    let hidden = owner.owner_proof_input_hash()?;
    let mut signers = transaction.signer_pk_hashes(width)?;
    signers.retain(|signer| *signer != hidden);
    signers.resize(width, [0; 32]);
    Ok(signers)
}

pub(crate) struct AnonymousAuthorizationPreparation<'a> {
    pub inputs: &'a [TransferInputUtxo],
    pub owner: &'a SigningKey,
    pub private_tx: &'a [u8; 32],
    pub external_data_hash: &'a [u8; 32],
    pub published_owners: &'a [[u8; 32]],
}

pub(crate) struct PreparedAnonymousAuthorization {
    pub authorization: AnonymousEddsaAuthorization,
    pub default_owner_tag: Option<[u8; 32]>,
}

impl AnonymousAuthorizationPreparation<'_> {
    pub fn prepare(self) -> Result<PreparedAnonymousAuthorization, ClientError> {
        let owner = self.owner.pubkey();
        let owner_public_key = owner.as_ed25519()?;
        // The hidden identity is published only when a default-ring UTXO of the
        // hidden owner is spent. A ring-bound hidden spend is anonymous, so it may
        // not coexist with a default-ring spend and no published output owner may
        // name the identity while it happens.
        let owner_pk_hash = solana_owner_identity(&owner_public_key)?;
        let spends = hidden_spend_rings(self.inputs, &owner);
        if !spends.default_ring && !spends.bound_ring {
            return Err(ClientError::AnonymousProofWithoutHiddenInput);
        }
        if spends.default_ring && spends.bound_ring {
            return Err(ClientError::AnonymousRingEddsaMixedDefaultAndRingSpend);
        }
        if spends.bound_ring {
            if let Some(index) = self
                .published_owners
                .iter()
                .position(|published| *published == owner_pk_hash)
            {
                return Err(ClientError::AnonymousRingEddsaPublishedOwnerLeaksIdentity { index });
            }
        }
        let default_owner_tag = spends.default_ring.then_some(owner_public_key);
        let default_owner_pk_hash = match default_owner_tag {
            Some(_) => owner_pk_hash,
            None => [0u8; 32],
        };
        let signed = sign_transact_digest(self.owner, self.private_tx, self.external_data_hash)?;

        Ok(PreparedAnonymousAuthorization {
            authorization: AnonymousEddsaAuthorization {
                owner_public_key: signed.owner_public_key,
                owner_signature: signed.owner_signature,
                message_digest: signed.message_digest,
                default_owner_pk_hash,
            },
            default_owner_tag,
        })
    }
}

/// An owner's Ed25519 signature over the transact message digest, the
/// authorization every in-circuit signature rail verifies.
pub(crate) struct SignedTransactDigest {
    pub owner_public_key: [u8; 32],
    pub owner_signature: [u8; 64],
    pub message_digest: [u8; 32],
}

pub(crate) fn sign_transact_digest(
    owner: &SigningKey,
    private_tx: &[u8; 32],
    external_data_hash: &[u8; 32],
) -> Result<SignedTransactDigest, ClientError> {
    let message_digest = transact_message_hash(private_tx, external_data_hash);
    Ok(SignedTransactDigest {
        owner_public_key: owner.pubkey().as_ed25519()?,
        owner_signature: owner.sign_message(&message_digest)?,
        message_digest,
    })
}

/// Which rings the proof's spent hidden-owner UTXOs belong to. Only spends
/// count: an address slot creates nothing that names an owner, so it neither
/// publishes the hidden identity nor forbids a ring spend.
struct HiddenSpendRings {
    default_ring: bool,
    bound_ring: bool,
}

fn hidden_spend_rings(inputs: &[TransferInputUtxo], owner: &PublicKey) -> HiddenSpendRings {
    let mut rings = HiddenSpendRings {
        default_ring: false,
        bound_ring: false,
    };
    for input_utxo in inputs {
        if input_utxo.utxo.is_dummy() || input_utxo.utxo.utxo.owner != *owner {
            continue;
        }
        if input_utxo.utxo.utxo.ring_program_id.is_some() {
            rings.bound_ring = true;
        } else {
            rings.default_ring = true;
        }
    }
    rings
}

impl AnonymousEddsaAuthorization {
    /// The public input hash fields that follow `private_tx_hash`.
    pub(crate) fn public_fields(&self) -> Result<[[u8; 32]; 2], ClientError> {
        Ok([
            hash_bytes(&self.message_digest)?,
            self.default_owner_pk_hash,
        ])
    }

    /// Encodes the same owner authorization for complete and indexed witnesses.
    pub(crate) fn fields(&self) -> Map<String, Value> {
        let (high, low) = self.message_digest.split_at(16);
        [
            ("ownerPublicKey", hex::encode(self.owner_public_key)),
            ("ownerSignature", hex::encode(self.owner_signature)),
            ("messageHashLow", hex::encode(low)),
            ("messageHashHigh", hex::encode(high)),
        ]
        .into_iter()
        .map(|(name, value)| (name, format!("0x{value}")))
        .chain([("defaultOwnerPkHash", hex_field(&self.default_owner_pk_hash))])
        .map(|(name, value)| (name.to_string(), Value::String(value)))
        .collect()
    }
}

impl ProveRequest for AnonymousEddsaTransferInputs {
    /// The Solana-only wire form with the circuit type and the owner fields of
    /// the prover's `AnonymousEddsaTransferParametersJSON`.
    fn body(&self) -> Result<Zeroizing<String>, ClientError> {
        let mut body: Map<String, Value> = serde_json::from_str(&to_json_ring(&self.transfer)?)
            .expect("the transfer request is a JSON object");
        body.insert(
            "circuitType".to_string(),
            Value::String("transfer-eddsa-ring".to_string()),
        );
        body.extend(self.authorization.fields());
        Ok(Zeroizing::new(Value::Object(body).to_string()))
    }

    fn proving_key(&self) -> Result<ExpectedProvingKey, ClientError> {
        ExpectedProvingKey::transfer_anonymous_ring_eddsa(
            self.transfer.inputs.len(),
            self.transfer.outputs.len(),
        )
    }

    fn delivery(&self) -> Delivery {
        Delivery::InResponse
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The body splits the digest into the prover's limbs and carries every key
    /// of the committed Go request.
    #[test]
    fn body_carries_the_prover_owner_fields() {
        let inputs = AnonymousEddsaTransferInputs {
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
                published_output_owner_pk_hashes: vec![BigUint::from(14u8)],
                cache: Default::default(),
                public_input_hash: BigUint::ZERO,
            },
            authorization: AnonymousEddsaAuthorization {
                owner_public_key: [1u8; 32],
                owner_signature: [2u8; 64],
                message_digest: core::array::from_fn(|index| index as u8),
                default_owner_pk_hash: [3u8; 32],
            },
        };
        let body: Value = serde_json::from_str(&inputs.body().unwrap()).unwrap();
        assert_eq!(body["circuitType"], "transfer-eddsa-ring");
        assert_eq!(body["ownerPublicKey"], format!("0x{}", "01".repeat(32)));
        assert_eq!(body["ownerSignature"], format!("0x{}", "02".repeat(64)));
        assert_eq!(
            body["messageHashHigh"],
            "0x000102030405060708090a0b0c0d0e0f"
        );
        assert_eq!(body["messageHashLow"], "0x101112131415161718191a1b1c1d1e1f");
        assert_eq!(
            body["defaultOwnerPkHash"],
            format!("0x3{}", "03".repeat(31))
        );
        assert_eq!(body["publishedOutputOwnerPkHashes"][0], "0xe");

        let request: Map<String, Value> = serde_json::from_str(include_str!(
            "../../../../../prover/server/prover/transfer_eddsa/testdata/eddsa-ring-2x2.json"
        ))
        .unwrap();
        for key in request.keys() {
            assert!(body.get(key).is_some(), "{key}");
        }
    }
}
