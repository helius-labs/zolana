//! The `CircuitId::ConfidentialEddsa` request: one owner signs the transaction
//! message digest with its Ed25519 key, and the proof verifies that signature,
//! so the owner does not sign the transaction. Every other input owner still
//! signs the transaction, as on the signer rail. The proof itself is built by
//! [`TransferProver`](crate::prover::TransferProver) on
//! [`ConfidentialEddsaRail`](crate::prover::ConfidentialEddsaRail).

use spr_hasher::primitives::{hash_bytes, solana_owner_identity};
use spr_interface::{
    verifying_keys::{Bsb22Commitment, CacheAccess, CircuitId, EddsaProofData},
    N_PUBLIC_SLOTS,
};
use spr_keypair::PublicKey;
use spr_transaction::instructions::transact::SppProofInputs;
use zeroize::Zeroizing;

use crate::{
    error::ClientError,
    prover::{
        client::{Delivery, ProveRequest},
        json::{to_json_signed, OwnerSignatureJson},
        proving_key::ExpectedProvingKey,
        Shape, TransferInputs,
    },
};

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
        eddsa_proof_data(self.owner_public_key)
    }

    /// The selector of a proof on this rail for `shape`, cached or not.
    pub fn circuit(&self, shape: Shape, cache_access: Option<CacheAccess>) -> CircuitId {
        confidential_eddsa_circuit(shape, self.owner_public_key, cache_access)
    }

    /// Encodes the owner authorization for complete and indexed proof inputs.
    pub(crate) fn json(&self) -> OwnerSignatureJson {
        OwnerSignatureJson::new(self, None)
    }
}

/// The `ConfidentialEddsa` selector for `shape` and the owner's raw Ed25519
/// key, before the proof fills in its commitment.
pub(crate) fn confidential_eddsa_circuit(
    shape: Shape,
    owner_pk: [u8; 32],
    cache_access: Option<CacheAccess>,
) -> CircuitId {
    let (n_in, n_out) = (shape.n_inputs() as u8, shape.n_outputs() as u8);
    let slots = N_PUBLIC_SLOTS as u8;
    let proof_data = eddsa_proof_data(owner_pk);
    match cache_access {
        Some(access) => CircuitId::ConfidentialEddsaCached(n_in, n_out, slots, proof_data, access),
        None => CircuitId::ConfidentialEddsa(n_in, n_out, slots, proof_data),
    }
}

fn eddsa_proof_data(owner_pk: [u8; 32]) -> EddsaProofData {
    EddsaProofData {
        bsb22_commitment: Bsb22Commitment {
            commitment: [0; 32],
            commitment_pok: [0; 32],
        },
        owner_pk,
    }
}

impl ProveRequest for ConfidentialEddsaTransferInputs {
    /// The signer-rail body with the circuit type and the owner fields of the
    /// prover's `ConfidentialEddsaTransferParametersJSON`.
    fn body(&self) -> Result<Zeroizing<String>, ClientError> {
        to_json_signed(
            &self.transfer,
            "transfer-confidential-eddsa",
            self.authorization.json(),
        )
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
    use crate::prover::{
        transact::{
            transfer::{ConfidentialEddsaRail, TransferProver},
            OwnerAuthorization, TransferInputUtxo,
        },
        TransferInputs,
    };
    use num_bigint::BigUint;
    use serde_json::{Map, Value};
    use spr_keypair::SigningKey;
    use spr_transaction::{ExternalData, SppProofOutputUtxo};

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
            let result = TransferProver {
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
                shape,
                cache_accounts: Default::default(),
                rail: ConfidentialEddsaRail {
                    owner: OwnerAuthorization::SigningKey(&owner),
                },
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
