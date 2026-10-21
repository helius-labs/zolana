//! Anonymous custom-ring transfer proof builder. The hidden Ed25519 owner signs
//! the ring spend message over the transaction digest, and the proof verifies
//! that signature and keeps the owner distinct from every public party.

use num_bigint::BigUint;
use serde_json::{Map, Value};
use solana_address::Address;
use zeroize::Zeroizing;
use zolana_hasher::primitives::hash_bytes;
use zolana_interface::instruction::instruction_data::transact::{
    AnonymousParties, TreeContext, ANONYMOUS_PARTIES,
};
use zolana_keypair::{PublicKey, SigningKey};
use zolana_transaction::{
    instructions::transact::{
        ring_spend_message, transact_message_hash, PublicTransfers, SettlementTransfer,
        SppProofInputs,
    },
    ExternalData, SppProofOutputUtxo,
};

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
            assemble_transaction, confidential_marked_output_owner_pk_hashes, ring_secrets,
            validate_shape, AssembledTransaction, OwnerMode, PublicInputs, TransferInputUtxo,
        },
        Shape, TransferInputs, TreeSlotFields,
    },
};

/// The hidden owner's signature over the ring spend message, made before the proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HiddenOwnerAuthorization {
    pub public_key: [u8; 32],
    pub signature: [u8; 64],
}

impl HiddenOwnerAuthorization {
    pub fn sign(
        owner: &SigningKey,
        ring_program_id: &Address,
        message_digest: &[u8; 32],
    ) -> Result<Self, ClientError> {
        Ok(Self {
            public_key: owner.pubkey().as_ed25519()?,
            signature: owner.sign_message(&ring_spend_message(ring_program_id, message_digest))?,
        })
    }

    pub fn owner(&self) -> PublicKey {
        PublicKey::from_ed25519(&self.public_key)
    }

    /// Fails before proving, the circuit refuses the same signature.
    pub fn verify(
        &self,
        ring_program_id: &Address,
        message_digest: &[u8; 32],
    ) -> Result<(), ClientError> {
        let message = ring_spend_message(ring_program_id, message_digest);
        if !self.owner().verify_message(&message, &self.signature) {
            return Err(ClientError::AnonymousSpendSignatureInvalid);
        }
        Ok(())
    }
}

pub struct AnonymousRingEddsaProver {
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
    pub owner: HiddenOwnerAuthorization,
    pub payer: Address,
    /// The ring's configured co-signer, `None` without one.
    pub cosigner: Option<Address>,
    /// The owner SPP reads from the SPL withdrawal's token account, `None` without one.
    pub exit_token_owner: Option<Address>,
    pub ring_program_id: Address,
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
    /// Preimage of the public ring id, bound inside the signed message.
    pub ring_program_address: [u8; 32],
    pub message_digest: [u8; 32],
    /// Program-derived public hash of the hidden owner when it spends a
    /// default-ring UTXO, zero otherwise.
    pub default_owner_pk_hash: [u8; 32],
    /// Payer, co-signer and exit destination identities, zero when absent.
    pub parties: [[u8; 32]; ANONYMOUS_PARTIES],
}

impl AnonymousRingEddsaProver {
    pub fn build(self) -> Result<AnonymousRingEddsaProofResult, ClientError> {
        let shape = self.shape;
        validate_shape(shape, self.inputs.len(), self.outputs.len())?;
        if self.signer_pk_hashes.len() != shape.signer_width() {
            return Err(ClientError::WitnessInputCountMismatch {
                got: self.signer_pk_hashes.len(),
                expected: shape.signer_width(),
            });
        }
        self.external_data
            .validate_ring_output_markers(&self.outputs)?;

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
            &OwnerMode::AnonymousEddsa(self.owner.owner()),
            self.allow_dummy_inputs,
        )?;
        let published_output_owner_pk_hashes =
            confidential_marked_output_owner_pk_hashes(&self.external_data, self.outputs.len())?;
        let PreparedAnonymousAuthorization {
            authorization,
            default_owner_tag,
        } = AnonymousAuthorizationPreparation {
            inputs: &self.inputs,
            owner: &self.owner,
            ring_program_id: &self.ring_program_id,
            payer: &self.payer,
            cosigner: self.cosigner.as_ref(),
            exit_token_owner: self.exit_token_owner.as_ref(),
            external_data: &self.external_data,
            private_tx: &private_tx,
            external_data_hash: &external_data_hash,
            published_owners: &published_output_owner_pk_hashes,
        }
        .prepare()?;

        let ring_program_id = hash_bytes(self.ring_program_id.as_array())?;
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
            ring_secrets: ring_secrets(&self.outputs),
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

/// The key every withdrawal of the transaction names, `None` without one.
pub fn anonymous_exit_destination(
    external_data: &ExternalData,
    exit_token_owner: Option<&Address>,
) -> Result<Option<Address>, ClientError> {
    let withdrawals = external_data
        .interface_transfers
        .iter()
        .filter(|transfer| !transfer.is_deposit());
    let spl = withdrawals
        .clone()
        .any(|transfer| matches!(transfer, SettlementTransfer::Spl { .. }));
    if spl != exit_token_owner.is_some() {
        return Err(ClientError::AnonymousExitTokenOwnerMismatch);
    }
    // SPP binds an SPL leg's token account owner, never the token account address.
    let keys = withdrawals
        .map(|transfer| match transfer {
            SettlementTransfer::Sol {
                user_sol_account, ..
            } => Some(user_sol_account.as_array()),
            SettlementTransfer::Spl { .. } => exit_token_owner.map(Address::as_array),
        })
        .collect::<Option<Vec<_>>>()
        .ok_or(ClientError::AnonymousExitTokenOwnerMismatch)?;
    Ok(AnonymousParties::exit_destination(keys.into_iter())?
        .map(|exit| Address::new_from_array(*exit)))
}

pub(crate) struct AnonymousAuthorizationPreparation<'a> {
    pub inputs: &'a [TransferInputUtxo],
    pub owner: &'a HiddenOwnerAuthorization,
    pub ring_program_id: &'a Address,
    pub payer: &'a Address,
    pub cosigner: Option<&'a Address>,
    pub exit_token_owner: Option<&'a Address>,
    pub external_data: &'a ExternalData,
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
        let owner = self.owner.owner();
        // The hidden identity is published only when a default-ring UTXO of the
        // hidden owner is spent. A ring-bound hidden spend is anonymous, so it may
        // not coexist with a default-ring spend and no published output owner may
        // name the identity while it happens.
        let owner_pk_hash = owner.owner_proof_input_hash()?;
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
        let default_owner_tag = spends.default_ring.then_some(self.owner.public_key);
        let default_owner_pk_hash = match default_owner_tag {
            Some(_) => owner_pk_hash,
            None => [0u8; 32],
        };
        let message_digest = transact_message_hash(self.private_tx, self.external_data_hash);
        self.owner.verify(self.ring_program_id, &message_digest)?;
        let exit_destination =
            anonymous_exit_destination(self.external_data, self.exit_token_owner)?;
        let parties = AnonymousParties {
            payer: self.payer.as_array(),
            cosigner: self.cosigner.map(Address::as_array),
            exit_destination: exit_destination.as_ref().map(Address::as_array),
        }
        .identities()?;

        Ok(PreparedAnonymousAuthorization {
            authorization: AnonymousEddsaAuthorization {
                owner_public_key: self.owner.public_key,
                owner_signature: self.owner.signature,
                ring_program_address: *self.ring_program_id.as_array(),
                message_digest,
                default_owner_pk_hash,
                parties,
            },
            default_owner_tag,
        })
    }
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
    pub(crate) fn public_fields(&self) -> Result<[[u8; 32]; 5], ClientError> {
        let [payer, cosigner, exit_destination] = self.parties;
        Ok([
            hash_bytes(&self.message_digest)?,
            self.default_owner_pk_hash,
            payer,
            cosigner,
            exit_destination,
        ])
    }

    /// Encodes the same owner authorization for complete and indexed witnesses.
    pub(crate) fn fields(&self) -> Map<String, Value> {
        let (high, low) = self.message_digest.split_at(16);
        let [payer, cosigner, exit_destination] = &self.parties;
        [
            ("ownerPublicKey", hex::encode(self.owner_public_key)),
            ("ownerSignature", hex::encode(self.owner_signature)),
            ("ringProgramAddress", hex::encode(self.ring_program_address)),
            ("messageHashLow", hex::encode(low)),
            ("messageHashHigh", hex::encode(high)),
        ]
        .into_iter()
        .map(|(name, value)| (name, format!("0x{value}")))
        .chain([
            ("defaultOwnerPkHash", hex_field(&self.default_owner_pk_hash)),
            ("payerPkHash", hex_field(payer)),
            ("cosignerPkHash", hex_field(cosigner)),
            ("exitDestinationPkHash", hex_field(exit_destination)),
        ])
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
                ring_secrets: vec![BigUint::from(7u8)],
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
                ring_program_address: [5u8; 32],
                message_digest: core::array::from_fn(|index| index as u8),
                default_owner_pk_hash: [3u8; 32],
                parties: [[4u8; 32], [0u8; 32], [6u8; 32]],
            },
        };
        let body: Value = serde_json::from_str(&inputs.body().unwrap()).unwrap();
        assert_eq!(body["circuitType"], "transfer-eddsa-ring");
        assert_eq!(body["ownerPublicKey"], format!("0x{}", "01".repeat(32)));
        assert_eq!(body["ownerSignature"], format!("0x{}", "02".repeat(64)));
        assert_eq!(body["ringProgramAddress"], format!("0x{}", "05".repeat(32)));
        assert_eq!(
            body["messageHashHigh"],
            "0x000102030405060708090a0b0c0d0e0f"
        );
        assert_eq!(body["messageHashLow"], "0x101112131415161718191a1b1c1d1e1f");
        assert_eq!(
            body["defaultOwnerPkHash"],
            format!("0x3{}", "03".repeat(31))
        );
        assert_eq!(body["payerPkHash"], format!("0x4{}", "04".repeat(31)));
        assert_eq!(body["cosignerPkHash"], "0x0");
        assert_eq!(
            body["exitDestinationPkHash"],
            format!("0x6{}", "06".repeat(31))
        );
        assert_eq!(body["publishedOutputOwnerPkHashes"][0], "0xe");
        assert_eq!(body["ringSecrets"][0], "0x7");

        let request: Map<String, Value> = serde_json::from_str(include_str!(
            "../../../../../prover/server/prover/transfer_eddsa/testdata/eddsa-ring-2x2.json"
        ))
        .unwrap();
        for key in request.keys() {
            assert!(body.get(key).is_some(), "{key}");
        }
    }

    /// The proof binds the key SPP reads, an SPL leg's token account owner.
    #[test]
    fn the_exit_key_is_the_sol_recipient_or_the_token_account_owner() {
        let recipient = Address::new_from_array([1; 32]);
        let token_account = Address::new_from_array([2; 32]);
        let owner = Address::new_from_array([3; 32]);
        let sol = SettlementTransfer::Sol {
            is_deposit: false,
            amount: 1,
            user_sol_account: recipient,
        };
        let spl = SettlementTransfer::Spl {
            mint: Address::new_from_array([4; 32]),
            is_deposit: false,
            amount: 1,
            user_spl_token: token_account,
        };
        let exit = |legs: Vec<SettlementTransfer>, token_owner: Option<&Address>| {
            let external_data = ExternalData {
                instruction_discriminator: 0,
                expiry_unix_ts: 0,
                interface_transfers: legs,
                data_hash: None,
                ring_data_hash: None,
                tx_viewing_pk: [0; 33],
                salt: [0; 16],
                outputs: Vec::new(),
                resolved_owner_tags: Vec::new(),
                messages: Vec::new(),
            };
            anonymous_exit_destination(&external_data, token_owner)
        };
        assert_eq!(exit(vec![sol], None).unwrap(), Some(recipient));
        assert_eq!(exit(vec![spl], Some(&owner)).unwrap(), Some(owner));
        assert_eq!(
            exit(vec![sol, spl], Some(&recipient)).unwrap(),
            Some(recipient)
        );
        assert_eq!(exit(Vec::new(), None).unwrap(), None);
        for (legs, token_owner) in [(vec![spl], None), (vec![sol], Some(&owner))] {
            assert!(matches!(
                exit(legs, token_owner),
                Err(ClientError::AnonymousExitTokenOwnerMismatch)
            ));
        }
        assert!(matches!(
            exit(vec![sol, spl], Some(&owner)),
            Err(ClientError::ShieldedPool(
                zolana_interface::error::ShieldedPoolError::AnonymousExitDestinationsDiffer
            ))
        ));
    }

    /// The signature binds the ring, the digest and the owner key.
    #[test]
    fn hidden_owner_authorization_verifies_only_its_own_message() {
        let owner = SigningKey::from_ed25519_bytes(&[7u8; 32]);
        let ring = Address::new_from_array([0x5A; 32]);
        let digest = [9u8; 32];
        let authorization = HiddenOwnerAuthorization::sign(&owner, &ring, &digest).unwrap();
        authorization.verify(&ring, &digest).unwrap();
        assert!(matches!(
            authorization.verify(&Address::new_from_array([0x5B; 32]), &digest),
            Err(ClientError::AnonymousSpendSignatureInvalid)
        ));
        assert!(matches!(
            authorization.verify(&ring, &[8u8; 32]),
            Err(ClientError::AnonymousSpendSignatureInvalid)
        ));
        let other = HiddenOwnerAuthorization {
            public_key: SigningKey::from_ed25519_bytes(&[8u8; 32])
                .pubkey()
                .as_ed25519()
                .unwrap(),
            ..authorization
        };
        assert!(matches!(
            other.verify(&ring, &digest),
            Err(ClientError::AnonymousSpendSignatureInvalid)
        ));
    }
}
