use super::*;
use zolana_client::{MerkleContext, MerkleProof, NULLIFIER_TREE_HEIGHT, STATE_TREE_HEIGHT};

fn withdrawal_request(smart_account: bool) -> SquadsSpendRequest {
    let owner = SigningKey::from_ed25519_bytes(&[3; 32]).pubkey();
    let context = MerkleContext {
        tree_type: 1,
        tree: pda::tree(0),
    };
    let nullifier_proof = NonInclusionProof {
        leaf: [0; 32],
        merkle_context: context.clone(),
        path: vec![[0; 32]; NULLIFIER_TREE_HEIGHT],
        root: [0; 32],
        root_seq: 0,
        root_index: 0,
        low_element: [0; 32],
        high_element: [0; 32],
        low_element_index: 0,
        high_element_index: 0,
    };
    SquadsSpendRequest {
        sender: SquadsSender {
            owner: if smart_account {
                SquadsOwner::SmartAccount
            } else {
                SquadsOwner::Ed25519(owner.as_ed25519().unwrap())
            },
            owner_identity: owner.owner_proof_input_hash().unwrap(),
            nullifier_key: NullifierKey::from_secret([2; 31]),
            viewing_secret: X25519Keypair::from_bytes(&[7; 32]),
            view_tag: [8; 32],
        },
        inputs: vec![SquadsSpendInput {
            asset: SOL_MINT,
            amount: 10,
            blinding: [1; 32],
            tree_id: 0,
            leaf_index: 0,
            spend_proof: SpendProof {
                state: MerkleProof {
                    leaf: [0; 32],
                    merkle_context: context,
                    path: vec![[0; 32]; STATE_TREE_HEIGHT],
                    leaf_index: 0,
                    root: [0; 32],
                    root_seq: 0,
                    root_index: 0,
                },
                nullifier: nullifier_proof.clone(),
            },
        }],
        dummy: smart_account.then_some(SquadsDummyInput {
            blinding: [9; 32],
            nullifier_proof,
        }),
        operation: SquadsSpendOperation::Withdrawal {
            amount: 4,
            settlement: WithdrawalSettlement::Sol {
                recipient: Address::new_from_array([5; 32]),
            },
        },
        payer: Address::new_from_array([6; 32]),
        output_tree_id: 0,
        expiry_unix_ts: 100,
        proposal: None,
        prover_url: "http://127.0.0.1:1".into(),
    }
}

#[test]
fn withdrawals_use_supported_spp_shapes_without_publishing_padding_outputs() {
    for smart_account in [false, true] {
        let probe = probe_squads_spend(withdrawal_request(smart_account)).unwrap();
        assert_eq!(
            (
                probe.shape,
                probe.spp_inputs.external_data.outputs.len(),
                probe.ring.inputs.len(),
                probe.ring.outputs.len()
            ),
            (Shape::new(if smart_account { 2 } else { 1 }, 2), 1, 1, 1),
        );
        let padding = probe.spp_inputs.output_utxos.last().unwrap();
        let first_nullifier = probe.spp_inputs.first_nullifier().unwrap();
        let output_seed = zolana_transaction::derive_output_blinding_seed(
            &first_nullifier,
            &probe.spp_inputs.blinding_seed,
        )
        .unwrap();
        let padding_blinding = zolana_transaction::utxo::derive_transact_output_blinding(
            &first_nullifier,
            &output_seed,
            1,
        )
        .unwrap();
        assert_eq!(
            (padding.is_compact(), padding.blinding),
            (true, padding_blinding)
        );
        assert_eq!(probe.spp_inputs.message_hash().unwrap(), probe.message_hash);
    }
}

#[test]
fn detached_spend_signature_binds_the_external_transaction_data() {
    let owner = SigningKey::from_ed25519_bytes(&[3; 32]);
    let request = withdrawal_request(false);
    let mut changed = withdrawal_request(false);
    changed.expiry_unix_ts += 1;
    let original = probe_squads_spend(request).unwrap();
    let changed = probe_squads_spend(changed).unwrap();
    let signature = sign_spend(&owner, &original.message_hash).unwrap();
    assert_eq!(original.private_tx_hash, changed.private_tx_hash);
    assert!(owner
        .pubkey()
        .verify_message(&original.message_hash, &signature));
    assert!(!owner
        .pubkey()
        .verify_message(&changed.message_hash, &signature));
}
