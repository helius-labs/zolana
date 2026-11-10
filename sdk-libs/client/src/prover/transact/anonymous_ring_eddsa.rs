//! The anonymous custom-ring transfer request. The hidden Ed25519 owner signs
//! the transaction message digest, and the proof verifies that signature. The
//! proof itself is built by [`TransferProver`](crate::prover::TransferProver)
//! on [`AnonymousRingEddsaRail`](crate::prover::AnonymousRingEddsaRail).

use spr_hasher::primitives::{hash_bytes, solana_owner_identity};
use spr_keypair::PublicKey;
use spr_transaction::instructions::transact::SppProofInputs;
use zeroize::Zeroizing;

use crate::{
    error::ClientError,
    prover::{
        client::{Delivery, ProveRequest},
        json::to_json_signed,
        json::OwnerSignatureJson,
        proving_key::ExpectedProvingKey,
        transact::{
            assembly::TransferInputUtxo, transfer::rail::PreparedAnonymousAuthorization,
            EddsaAuthorization, OwnerAuthorization,
        },
        TransferInputs,
    },
};

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

/// Signer identities without the hidden owner, which authorizes only inside the proof.
pub fn anonymous_signer_pk_hashes(
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
    pub owner: OwnerAuthorization<'a>,
    pub private_tx: &'a [u8; 32],
    pub external_data_hash: &'a [u8; 32],
    pub published_owners: &'a [[u8; 32]],
}

impl AnonymousAuthorizationPreparation<'_> {
    pub fn prepare(self) -> Result<PreparedAnonymousAuthorization, ClientError> {
        let owner = self.owner.public_key();
        let owner_public_key = owner.as_ed25519()?;
        // The hidden identity is published only when a default-ring UTXO of the
        // hidden owner is spent. A ring-bound hidden spend is anonymous, so it may
        // not coexist with a default-ring spend and no published output owner may
        // name the identity while it happens.
        let owner_pk_hash = solana_owner_identity(&owner_public_key)?;
        let spends = hidden_spend_rings(self.inputs, &owner);
        if !spends.address_slot && !spends.default_ring && !spends.bound_ring {
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
        let signed = self
            .owner
            .authorize(self.private_tx, self.external_data_hash)?;

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

/// Which rings the proof's spent hidden-owner UTXOs belong to. Only spends
/// count: an address slot creates nothing that names an owner, so it neither
/// publishes the hidden identity nor forbids a ring spend.
struct HiddenSpendRings {
    /// Satisfies the hidden input requirement and nothing else.
    address_slot: bool,
    default_ring: bool,
    bound_ring: bool,
}

fn hidden_spend_rings(inputs: &[TransferInputUtxo], owner: &PublicKey) -> HiddenSpendRings {
    let mut rings = HiddenSpendRings {
        address_slot: false,
        default_ring: false,
        bound_ring: false,
    };
    for input_utxo in inputs {
        if input_utxo.utxo.is_dummy() || input_utxo.utxo.utxo.owner != *owner {
            continue;
        }
        if input_utxo.utxo.is_address() {
            rings.address_slot = true;
        } else if input_utxo.utxo.utxo.ring_program_id.is_some() {
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
    pub(crate) fn json(&self) -> OwnerSignatureJson {
        OwnerSignatureJson::new(
            &EddsaAuthorization {
                owner_public_key: self.owner_public_key,
                owner_signature: self.owner_signature,
                message_digest: self.message_digest,
            },
            Some(&self.default_owner_pk_hash),
        )
    }
}

impl ProveRequest for AnonymousEddsaTransferInputs {
    /// The Solana-only wire form with the circuit type and the owner fields of
    /// the prover's `AnonymousEddsaTransferParametersJSON`.
    fn body(&self) -> Result<Zeroizing<String>, ClientError> {
        to_json_signed(
            &self.transfer,
            "transfer-eddsa-ring",
            self.authorization.json(),
        )
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
    use num_bigint::BigUint;
    use serde_json::{Map, Value};

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
