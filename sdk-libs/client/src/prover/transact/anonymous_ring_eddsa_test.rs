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

use crate::{
    authority::ProofAuthority,
    prover::transact::ring_eddsa::RingTransferProver,
    rpc::{
        MerkleContext, MerkleProof, NonInclusionProof, NULLIFIER_TREE_HEIGHT, STATE_TREE_HEIGHT,
    },
    SpendProof,
};
use zolana_keypair::ShieldedKeypair;
use zolana_transaction::{
    instructions::transact::PublicTransfers,
    utxo::{derive_output_blinding_seed, derive_transact_output_blinding, SppProofInputUtxo},
    Data, Mint, Utxo,
};

const RING: Address = Address::new_from_array([9; 32]);

fn signing_key(seed: u8) -> SigningKey {
    SigningKey::from_ed25519_bytes(&[seed; 32])
}

// These roots and paths are deterministic assembly inputs. The tests exercise
// authorization and request construction without starting a prover or indexer.
fn input(owner: &SigningKey, ring: Option<Address>, blinding: u8) -> TransferInputUtxo {
    let keys = ShieldedKeypair::from_keypair(owner.clone()).unwrap();
    let utxo = Utxo {
        owner: owner.pubkey(),
        asset: Mint::SOL,
        amount: 0,
        blinding: [blinding; 32],
        ring_program_id: ring,
        data: Data::default(),
    };
    let nullifier_pubkey = keys.nullifier_key.pubkey().unwrap();
    let utxo_hash = utxo.hash(&nullifier_pubkey, &[0; 32], &[0; 32], 0).unwrap();
    let nullifier = keys
        .nullifier_key
        .nullifier(&utxo_hash, &utxo.blinding)
        .unwrap();
    let utxo = SppProofInputUtxo {
        address: false,
        utxo,
        nullifier_pubkey,
        utxo_hash,
        nullifier,
        data_hash: None,
        ring_data_hash: None,
        tree_id: 0,
        leaf_index: 0,
        cache_slot: None,
        compact: false,
    };
    let context = MerkleContext {
        tree_type: 0,
        tree: zolana_interface::pda::tree(0),
    };
    TransferInputUtxo {
        proof: Some(SpendProof {
            state: MerkleProof {
                leaf: utxo_hash,
                merkle_context: context.clone(),
                path: vec![[0; 32]; STATE_TREE_HEIGHT],
                leaf_index: 0,
                root: [2; 32],
                root_seq: 0,
                root_index: 1,
            },
            nullifier: NonInclusionProof {
                leaf: nullifier,
                merkle_context: context,
                path: vec![[0; 32]; NULLIFIER_TREE_HEIGHT],
                low_element: [0; 32],
                low_element_index: 0,
                high_element: [3; 32],
                high_element_index: 1,
                root: [4; 32],
                root_seq: 0,
                root_index: 2,
            },
        }),
        nullifier_proof: None,
        utxo,
    }
}

fn inputs(owner: &SigningKey, ring: Option<Address>) -> Vec<TransferInputUtxo> {
    vec![input(owner, ring, 1), input(owner, ring, 2)]
}

fn prover(inputs: Vec<TransferInputUtxo>) -> RingTransferProver {
    let shape = Shape::new(2, 2);
    let blinding_seed = [5; 32];
    let seed = derive_output_blinding_seed(&inputs[0].utxo.nullifier, &blinding_seed).unwrap();
    let outputs = (0..shape.n_outputs())
        .map(|index| SppProofOutputUtxo {
            blinding: derive_transact_output_blinding(
                &inputs[0].utxo.nullifier,
                &seed,
                index as u32,
            )
            .unwrap(),
            ..Default::default()
        })
        .collect();
    RingTransferProver {
        inputs,
        outputs,
        blinding_seed,
        output_tree_id: 0,
        external_data: ExternalData::new([0; 33], [0; 16], Vec::new(), Vec::new(), Vec::new()),
        public_transfers: PublicTransfers::default(),
        signer_pk_hashes: vec![[0; 32]; shape.signer_width()],
        allow_dummy_inputs: true,
        ring_program_id: Some(RING),
        shape,
    }
}

fn build_with_signing_key(
    prover: RingTransferProver,
    owner: &SigningKey,
) -> AnonymousRingEddsaProofResult {
    AnonymousRingEddsaProver {
        inputs: prover.inputs,
        outputs: prover.outputs,
        blinding_seed: prover.blinding_seed,
        output_tree_id: prover.output_tree_id,
        external_data: prover.external_data,
        public_transfers: prover.public_transfers,
        signer_pk_hashes: prover.signer_pk_hashes,
        allow_dummy_inputs: prover.allow_dummy_inputs,
        owner,
        ring_program_id: prover.ring_program_id,
        shape: prover.shape,
    }
    .build()
    .unwrap()
}

#[test]
fn detached_authorization_matches_signing_key_request_and_metadata() {
    let owner = signing_key(7);
    for ring in [None, Some(RING)] {
        let inputs = inputs(&owner, ring);
        let mut expected = build_with_signing_key(prover(inputs.clone()), &owner);
        let mut actual = prover(inputs)
            .build_anonymous(
                owner.pubkey().as_ed25519().unwrap(),
                expected.inputs.authorization.owner_signature,
            )
            .unwrap();
        let keys = ShieldedKeypair::from_keypair(owner.clone()).unwrap();
        keys.complete_inputs(&mut expected.inputs.transfer.inputs)
            .unwrap();
        keys.complete_inputs(&mut actual.inputs.transfer.inputs)
            .unwrap();
        assert_eq!(
            serde_json::from_str::<Value>(&actual.inputs.body().unwrap()).unwrap(),
            serde_json::from_str::<Value>(&expected.inputs.body().unwrap()).unwrap(),
            "detached signing must assemble the complete same proof request"
        );
        assert_eq!(
            (
                actual.public_input_hash,
                actual.nullifiers,
                actual.output_hashes,
                actual.private_tx_hash,
                actual.tree_contexts,
                actual.input_tree_indexes,
                actual.default_owner_tag
            ),
            (
                expected.public_input_hash,
                expected.nullifiers,
                expected.output_hashes,
                expected.private_tx_hash,
                expected.tree_contexts,
                expected.input_tree_indexes,
                expected.default_owner_tag
            ),
            "detached signing must preserve instruction metadata"
        );
        assert_eq!(
            actual
                .inputs
                .transfer
                .inputs
                .iter()
                .map(|input| &input.owner_pk_hash)
                .collect::<Vec<_>>(),
            vec![&BigUint::ZERO; 2],
            "the hidden owner's input tags must stay private"
        );
    }
}

#[test]
fn detached_authorization_rejects_signature_from_another_key() {
    let owner = signing_key(7);
    let inputs = inputs(&owner, Some(RING));
    let signed = build_with_signing_key(prover(inputs.clone()), &owner);
    let signature = signing_key(8)
        .sign_message(&signed.inputs.authorization.message_digest)
        .unwrap();
    assert!(matches!(
        prover(inputs).build_anonymous(owner.pubkey().as_ed25519().unwrap(), signature),
        Err(ClientError::InvalidAnonymousOwnerSignature)
    ));
}

#[test]
fn detached_authorization_rejects_changed_external_data() {
    let owner = signing_key(7);
    let inputs = inputs(&owner, Some(RING));
    let signed = build_with_signing_key(prover(inputs.clone()), &owner);
    let mut changed = prover(inputs.clone());
    changed.external_data.salt[0] = 1;
    let rebuilt = build_with_signing_key(prover_with_changed_salt(inputs), &owner);
    assert_eq!(
        rebuilt.private_tx_hash, signed.private_tx_hash,
        "external data is outside the private transaction hash"
    );
    assert_ne!(
        rebuilt.inputs.authorization.message_digest, signed.inputs.authorization.message_digest,
        "the authorization digest must commit to external data separately"
    );
    assert!(matches!(
        changed.build_anonymous(
            owner.pubkey().as_ed25519().unwrap(),
            signed.inputs.authorization.owner_signature
        ),
        Err(ClientError::InvalidAnonymousOwnerSignature)
    ));
}

fn prover_with_changed_salt(inputs: Vec<TransferInputUtxo>) -> RingTransferProver {
    let mut prover = prover(inputs);
    prover.external_data.salt[0] = 1;
    prover
}

#[test]
fn detached_authorization_rejects_missing_hidden_input() {
    let owner = signing_key(7);
    let other = signing_key(8);
    assert!(matches!(
        prover(inputs(&other, Some(RING)))
            .build_anonymous(owner.pubkey().as_ed25519().unwrap(), [0; 64]),
        Err(ClientError::AnonymousProofWithoutHiddenInput)
    ));
}

#[test]
fn detached_authorization_rejects_published_hidden_owner() {
    use zolana_event::{OutputDataEncoding, CONFIDENTIAL_ENCRYPTED_SCHEME_TAG};
    use zolana_interface::instruction::{OwnerTag, TransactOutput};
    let owner = signing_key(7);
    let tag = owner.pubkey().as_ed25519().unwrap();
    let mut prover = prover(inputs(&owner, Some(RING)));
    prover.external_data.outputs.push(TransactOutput {
        utxo_hash: [0; 32],
        owner_tag: OwnerTag::Inline(tag),
        data: Some(
            borsh::to_vec(&OutputDataEncoding::Encrypted(vec![
                CONFIDENTIAL_ENCRYPTED_SCHEME_TAG,
                9,
            ]))
            .unwrap(),
        ),
    });
    prover.external_data.resolved_owner_tags.push(tag);
    assert!(matches!(
        prover.build_anonymous(tag, [0; 64]),
        Err(ClientError::AnonymousRingEddsaPublishedOwnerLeaksIdentity { index: 0 })
    ));
}

#[test]
fn detached_authorization_rejects_mixed_default_and_ring_spends() {
    let owner = signing_key(7);
    assert!(matches!(
        prover(vec![input(&owner, None, 1), input(&owner, Some(RING), 2)])
            .build_anonymous(owner.pubkey().as_ed25519().unwrap(), [0; 64]),
        Err(ClientError::AnonymousRingEddsaMixedDefaultAndRingSpend)
    ));
}
