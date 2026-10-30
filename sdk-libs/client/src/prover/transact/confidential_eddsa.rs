//! Default-ring transfer proof builder for `CircuitId::ConfidentialEddsa`: one
//! owner signs the transaction message digest with its Ed25519 key, and the
//! proof verifies that signature, so the owner does not sign the transaction.
//! Every other input owner still signs the transaction, as on the signer rail.

use num_bigint::BigUint;
use serde_json::{Map, Value};
use spr_hasher::primitives::{hash_bytes, solana_owner_identity};
use spr_interface::{
    instruction::instruction_data::transact::TreeContext,
    verifying_keys::{Bsb22Commitment, CacheAccess, CircuitId, EddsaProofData},
    N_PUBLIC_SLOTS,
};
use spr_keypair::PublicKey;
use spr_transaction::{
    instructions::transact::{CacheAccounts, PublicTransfers, SppProofInputs},
    ExternalData, SppProofOutputUtxo,
};
use zeroize::Zeroizing;

use crate::{
    error::ClientError,
    prover::{
        cache::CacheSelection,
        client::{Delivery, ProveRequest},
        field::be,
        json::to_json,
        proving_key::ExpectedProvingKey,
        transact::{
            assembly::{
                assemble_transaction, AssembledTransaction, OwnerMode, PublicInputs,
                TransferInputUtxo,
            },
            OwnerAuthorization,
        },
        Shape, TransferInputs, TreeSlotFields,
    },
};

pub struct ConfidentialEddsaProver<'a> {
    pub inputs: Vec<TransferInputUtxo>,
    pub outputs: Vec<SppProofOutputUtxo>,
    /// The transaction's private random root seed. See
    /// [`TransferProver::blinding_seed`](crate::prover::TransferProver).
    pub blinding_seed: [u8; 32],
    /// Raw id of the tree every output is appended to.
    pub output_tree_id: u16,
    pub external_data: ExternalData,
    pub public_transfers: PublicTransfers,
    /// The Solana owner signers, without the in-circuit owner.
    pub signer_pk_hashes: Vec<[u8; 32]>,
    pub allow_dummy_inputs: bool,
    /// The owner whose signature the proof verifies.
    pub owner: OwnerAuthorization<'a>,
    pub shape: Shape,
    pub cache_accounts: CacheAccounts,
}

#[derive(Debug, Clone)]
pub struct ConfidentialEddsaProofResult {
    pub inputs: ConfidentialEddsaTransferInputs,
    pub public_input_hash: [u8; 32],
    /// Every circuit slot's published value, 0 for compact padding; see
    /// [`TransferProofResult::nullifiers`](crate::prover::TransferProofResult).
    pub nullifiers: Vec<[u8; 32]>,
    pub output_hashes: Vec<[u8; 32]>,
    pub private_tx_hash: [u8; 32],
    pub tree_contexts: Vec<TreeContext>,
    /// The raw ids of the input trees, parallel to `tree_contexts`.
    pub tree_ids: Vec<u16>,
    /// Each input's index into `tree_contexts`, parallel to `nullifiers`.
    pub input_tree_indexes: Vec<u8>,
    pub cache_access: Option<CacheAccess>,
}

/// The signer-rail proof inputs plus the owner's authorization.
#[derive(Debug, Clone)]
pub struct ConfidentialEddsaTransferInputs {
    pub transfer: TransferInputs,
    pub authorization: EddsaAuthorization,
}

/// One owner's Ed25519 signature over the transaction message digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EddsaAuthorization {
    pub owner_public_key: [u8; 32],
    pub owner_signature: [u8; 64],
    pub message_digest: [u8; 32],
}

impl ConfidentialEddsaProver<'_> {
    pub fn build(self) -> Result<ConfidentialEddsaProofResult, ClientError> {
        let shape = self.shape;
        if !shape.is_confidential_eddsa()
            || shape.n_inputs() != self.inputs.len()
            || shape.n_outputs() != self.outputs.len()
        {
            return Err(ClientError::UnsupportedShape {
                n_in: self.inputs.len(),
                n_out: self.outputs.len(),
            });
        }
        if self.signer_pk_hashes.len() != shape.signer_width() {
            return Err(ClientError::WitnessInputCountMismatch {
                got: self.signer_pk_hashes.len(),
                expected: shape.signer_width(),
            });
        }
        let cache = CacheSelection::derive(
            &self.inputs,
            &self.outputs,
            self.cache_accounts,
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
            &OwnerMode::SolanaEddsa,
            self.allow_dummy_inputs,
        )?;
        let authorization = self.owner.authorize(&private_tx, &external_data_hash)?;
        let public_input = PublicInputs {
            nullifiers: &assembled_inputs.nullifiers,
            output_hashes: &assembled_outputs.output_hashes,
            tree_slots: &assembled_inputs.tree_slots,
            output_tree_id: self.output_tree_id,
            private_tx: &private_tx,
            external_data_hash: &external_data_hash,
            public_transfers: &self.public_transfers,
            ring_program_id: &[0u8; 32],
            input_flags: &input_flags,
            signer_pk_hashes: &self.signer_pk_hashes,
            output_owner_pk_hashes: Some(&assembled_outputs.output_owner_pk_hashes),
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
            ring_program_id: BigUint::ZERO,
            signer_pk_hashes: self.signer_pk_hashes.iter().map(be).collect(),
            input_flags: be(&input_flags),
            published_output_owner_pk_hashes: assembled_outputs
                .output_owner_pk_hashes
                .iter()
                .map(be)
                .collect(),
            cache: cache.proof_inputs,
            public_input_hash: be(&public_input),
        };

        Ok(ConfidentialEddsaProofResult {
            inputs: ConfidentialEddsaTransferInputs {
                transfer,
                authorization,
            },
            public_input_hash: public_input,
            nullifiers: assembled_inputs.nullifiers,
            output_hashes: assembled_outputs.output_hashes,
            private_tx_hash: private_tx,
            tree_contexts: assembled_inputs.tree_contexts,
            tree_ids: assembled_inputs.tree_ids,
            input_tree_indexes: assembled_inputs.input_tree_indexes,
            cache_access: cache.access,
        })
    }
}

/// The Solana owner signers of a transaction on this rail: every owner signer
/// but the in-circuit owner, which authorizes only inside the proof.
pub fn confidential_eddsa_signer_pk_hashes(
    transaction: &SppProofInputs,
    owner: &PublicKey,
) -> Result<Vec<[u8; 32]>, ClientError> {
    let width = transaction
        .check_shape_for(spr_transaction::instructions::transact::TransactRail::ConfidentialEddsa)?
        .signer_width();
    let in_circuit = owner.owner_proof_input_hash()?;
    let mut signers = transaction
        .owner_signer_pubkeys()?
        .iter()
        .map(|signer| solana_owner_identity(signer.as_array()))
        .collect::<Result<Vec<_>, _>>()?;
    signers.retain(|signer| *signer != in_circuit);
    if signers.len() > width {
        return Err(ClientError::UnsupportedShape {
            n_in: transaction.input_utxos.len(),
            n_out: transaction.output_utxos.len(),
        });
    }
    signers.resize(width, [0; 32]);
    Ok(signers)
}

impl EddsaAuthorization {
    /// The public input hash fields that follow `private_tx_hash`: the message
    /// hash and the chain of the verified owner identities, which for the one
    /// owner the selector carries is that identity.
    pub(crate) fn public_fields(&self) -> Result<[[u8; 32]; 2], ClientError> {
        Ok([
            hash_bytes(&self.message_digest)?,
            solana_owner_identity(&self.owner_public_key)?,
        ])
    }

    /// The selector payload before the proof fills in its commitment.
    pub fn proof_data(&self) -> EddsaProofData {
        EddsaProofData {
            bsb22_commitment: Bsb22Commitment {
                commitment: [0; 32],
                commitment_pok: [0; 32],
            },
            owner_pk: self.owner_public_key,
        }
    }

    /// The selector of a proof on this rail for `shape`, cached or not.
    pub fn circuit(&self, shape: Shape, cache_access: Option<CacheAccess>) -> CircuitId {
        let (n_in, n_out) = (shape.n_inputs() as u8, shape.n_outputs() as u8);
        let slots = N_PUBLIC_SLOTS as u8;
        match cache_access {
            Some(access) => {
                CircuitId::ConfidentialEddsaCached(n_in, n_out, slots, self.proof_data(), access)
            }
            None => CircuitId::ConfidentialEddsa(n_in, n_out, slots, self.proof_data()),
        }
    }

    /// Encodes the owner authorization for complete and indexed proof inputs.
    pub(crate) fn fields(&self) -> Map<String, Value> {
        let (high, low) = self.message_digest.split_at(16);
        [
            ("ownerPublicKey", hex::encode(self.owner_public_key)),
            ("ownerSignature", hex::encode(self.owner_signature)),
            ("messageHashLow", hex::encode(low)),
            ("messageHashHigh", hex::encode(high)),
        ]
        .into_iter()
        .map(|(name, value)| (name.to_string(), Value::String(format!("0x{value}"))))
        .collect()
    }
}

impl ProveRequest for ConfidentialEddsaTransferInputs {
    /// The signer-rail body with the circuit type and the owner fields of the
    /// prover's `ConfidentialEddsaTransferParametersJSON`.
    fn body(&self) -> Result<Zeroizing<String>, ClientError> {
        let mut body: Map<String, Value> = serde_json::from_str(&to_json(&self.transfer)?)
            .expect("the transfer request is a JSON object");
        body.insert(
            "circuitType".to_string(),
            Value::String("transfer-confidential-eddsa".to_string()),
        );
        body.extend(self.authorization.fields());
        Ok(Zeroizing::new(Value::Object(body).to_string()))
    }

    fn proving_key(&self) -> Result<ExpectedProvingKey, ClientError> {
        ExpectedProvingKey::transfer_confidential_eddsa(
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
    use spr_keypair::SigningKey;

    fn external_data() -> ExternalData {
        ExternalData {
            instruction_discriminator: 0,
            expiry_unix_ts: 0,
            interface_transfers: Vec::new(),
            data_hash: None,
            ring_data_hash: None,
            tx_viewing_pk: [0; 33],
            salt: [0; 16],
            outputs: Vec::new(),
            resolved_owner_tags: Vec::new(),
            messages: Vec::new(),
        }
    }

    #[test]
    fn build_validates_the_confidential_eddsa_shape_set() {
        use spr_transaction::utxo::SppProofInputUtxo;
        let owner = SigningKey::from_ed25519_bytes(&[1; 32]);
        for (shape, supported) in [
            (Shape::new(16, 16), true),
            (Shape::new(24, 8), true),
            (Shape::new(24, 16), true),
            (Shape::new(48, 8), true),
            (Shape::new(48, 16), true),
            (Shape::new(1, 2), false),
            (Shape::new(3, 2), false),
        ] {
            let result = ConfidentialEddsaProver {
                inputs: vec![
                    TransferInputUtxo {
                        utxo: SppProofInputUtxo::dummy(1).unwrap(),
                        proof: None,
                        nullifier_proof: None,
                    };
                    shape.n_inputs()
                ],
                outputs: vec![SppProofOutputUtxo::default(); shape.n_outputs()],
                blinding_seed: [0; 32],
                output_tree_id: 1,
                external_data: external_data(),
                public_transfers: Default::default(),
                signer_pk_hashes: Vec::new(),
                allow_dummy_inputs: true,
                owner: OwnerAuthorization::SigningKey(&owner),
                shape,
                cache_accounts: Default::default(),
            }
            .build();
            if supported {
                assert!(
                    matches!(
                        result,
                        Err(ClientError::WitnessInputCountMismatch { got: 0, .. })
                    ),
                    "{shape:?}: {result:?}"
                );
            } else {
                assert!(
                    matches!(result, Err(ClientError::UnsupportedShape { .. })),
                    "{shape:?}: {result:?}"
                );
            }
        }
    }

    #[test]
    fn proof_owner_does_not_consume_an_external_signer_slot() {
        use spr_keypair::ShieldedKeypair;
        use spr_transaction::{utxo::SppProofInputUtxo, Mint};
        let owners: Vec<_> = (1..=5)
            .map(|seed| {
                ShieldedKeypair::from_keypair(SigningKey::from_ed25519_bytes(&[seed; 32])).unwrap()
            })
            .collect();
        let owner = SigningKey::from_ed25519_bytes(&[1; 32]);
        let outputs = owners
            .iter()
            .map(|keypair| {
                let mut output =
                    SppProofOutputUtxo::new(Mint::SOL, 0, keypair.shielded_address().unwrap())
                        .unwrap();
                output.data_hash = Some([1; 32]);
                output
            })
            .collect::<Vec<_>>();
        let mut transaction = SppProofInputs {
            input_utxos: vec![SppProofInputUtxo::dummy(1).unwrap(); 2],
            output_utxos: outputs[..4].to_vec(),
            blinding_seed: [0; 32],
            output_tree_id: 1,
            external_data: external_data(),
            payer: Default::default(),
            cache_accounts: Default::default(),
        };
        transaction
            .output_utxos
            .resize(8, SppProofOutputUtxo::default());
        let expected = owners[1..4]
            .iter()
            .map(|keypair| keypair.signing_pubkey().owner_proof_input_hash().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(
            confidential_eddsa_signer_pk_hashes(&transaction, &owner.pubkey()).unwrap(),
            expected
        );
        transaction.output_utxos[4] = outputs[4].clone();
        assert!(matches!(
            confidential_eddsa_signer_pk_hashes(&transaction, &owner.pubkey()),
            Err(ClientError::UnsupportedShape { n_in: 2, n_out: 8 })
        ));
    }

    /// The body splits the digest into the prover's limbs and carries every key
    /// of the committed Go request.
    #[test]
    fn body_carries_the_prover_owner_fields() {
        let inputs = ConfidentialEddsaTransferInputs {
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
            authorization: EddsaAuthorization {
                owner_public_key: [1u8; 32],
                owner_signature: [2u8; 64],
                message_digest: core::array::from_fn(|index| index as u8),
            },
        };
        let body: Value = serde_json::from_str(&inputs.body().unwrap()).unwrap();
        assert_eq!(body["circuitType"], "transfer-confidential-eddsa");
        assert_eq!(body["ownerPublicKey"], format!("0x{}", "01".repeat(32)));
        assert_eq!(body["ownerSignature"], format!("0x{}", "02".repeat(64)));
        assert_eq!(
            body["messageHashHigh"],
            "0x000102030405060708090a0b0c0d0e0f"
        );
        assert_eq!(body["messageHashLow"], "0x101112131415161718191a1b1c1d1e1f");
        assert_eq!(body["ringProgramId"], "0x0");
        assert!(body.get("defaultOwnerPkHash").is_none());

        let request: Map<String, Value> = serde_json::from_str(include_str!(
            "../../../../../prover/server/prover/transfer_eddsa/testdata/confidential-eddsa-2x8.json"
        ))
        .unwrap();
        for key in request.keys() {
            assert!(body.get(key).is_some(), "{key}");
        }
    }

    /// The selector carries the signing key and an empty commitment for the
    /// proof to fill, on both the uncached and the cached variant.
    #[test]
    fn the_selector_carries_the_owner_key() {
        let authorization = EddsaAuthorization {
            owner_public_key: [7u8; 32],
            owner_signature: [0u8; 64],
            message_digest: [0u8; 32],
        };
        let proof_data = EddsaProofData {
            bsb22_commitment: Bsb22Commitment {
                commitment: [0; 32],
                commitment_pok: [0; 32],
            },
            owner_pk: [7u8; 32],
        };
        assert_eq!(
            authorization.circuit(Shape::IN2_OUT8, None),
            CircuitId::ConfidentialEddsa(2, 8, 3, proof_data)
        );
        let access = CacheAccess {
            read_bitmap: 1,
            write_slots: [spr_interface::verifying_keys::CacheWrite::NONE;
                spr_interface::verifying_keys::MAX_CACHE_WRITES],
        };
        assert_eq!(
            authorization.circuit(Shape::new(48, 16), Some(access)),
            CircuitId::ConfidentialEddsaCached(48, 16, 3, proof_data, access)
        );
    }
}
