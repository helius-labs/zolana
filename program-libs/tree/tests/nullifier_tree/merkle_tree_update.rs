use zolana_tree::nullifier_tree::{
    access::{get_merkle_tree_account_size, test_utils::init_tree_account_data},
    batch::CachedTreeUpdate,
    error::NullifierTreeError,
    merkle_tree_update::InstructionDataAddressAppendInputs,
    proof::CompressedProof,
};

/// Re-submitting a proof for a zkp batch that has already been applied
/// (its StartIndex lies behind the account next index) is a no-op: the proof
/// is not re-verified (an invalid proof still returns Ok) and no cached
/// update is written.
#[test]
fn test_replay_after_apply_is_noop() {
    let mut account_data = vec![0u8; get_merkle_tree_account_size::<4>()];
    let pubkey = [1u8; 32];
    let tree = init_tree_account_data::<4>(&mut account_data, 4, 1, 40, None)
        .unwrap();

    // Two zkp batches finalized, one already inserted -> num_inserted = 1.
    {
        let batch = tree.batches.get_mut(0).unwrap();
        batch.set_num_full_zkp_batches(2);
        batch.advance_state_to_full().unwrap();
        batch.mark_as_inserted_in_merkle_tree().unwrap();
    }
    assert_eq!(tree.batches.first().unwrap().get_num_inserted_zkps(), 1);

    // Replay zkp batch 0, which is behind the live next index, with an
    // invalid proof. Verification must be skipped, so the call succeeds.
    let result = tree
        .update_tree_from_address_queue(
            pubkey,
            InstructionDataAddressAppendInputs {
                new_root: [3u8; 32],
                old_root: [2u8; 32],
                zkp_batch_index: 0,
                compressed_proof: CompressedProof::default(),
            },
        )
        .unwrap();

    assert!(result.is_none());
    assert_eq!(tree.batches.first().unwrap().cached_tree_update(0), None);
}

/// Re-submitting a proof for a zkp batch that is already cached (an occupied
/// slot ahead of the inserted count) is verified like any other proof: an
/// invalid proof is rejected and the existing cached update is preserved.
#[test]
fn test_replay_while_cached_verifies_and_keeps_update_on_failure() {
    let mut account_data = vec![0u8; get_merkle_tree_account_size::<4>()];
    let pubkey = [1u8; 32];
    let tree = init_tree_account_data::<4>(&mut account_data, 4, 1, 40, None)
        .unwrap();

    // Finalize a zkp batch so zkp_batch_index 0 passes the readiness guard.
    tree.batches.get_mut(0).unwrap().set_num_full_zkp_batches(2);

    // Cache an update at zkp batch 0 of a freshly initialized address tree.
    let cached = CachedTreeUpdate {
        old_root: [9u8; 32],
        new_root: [8u8; 32],
        occupied: 1,
    };
    tree.batches
        .get_mut(0)
        .unwrap()
        .set_cached_tree_update(0, cached);

    // Re-submit zkp batch 0 with different roots and an invalid proof. The
    // occupied slot is ahead of the inserted count, so the proof is verified
    // and rejected; the stored update is preserved unchanged.
    let result = tree.update_tree_from_address_queue(
        pubkey,
        InstructionDataAddressAppendInputs {
            new_root: [3u8; 32],
            old_root: [2u8; 32],
            zkp_batch_index: 0,
            compressed_proof: CompressedProof::default(),
        },
    );

    // Reaching the verifier at all is the point: this tree's zkp batch size has
    // no circuit, so verification is attempted and rejected rather than skipped.
    assert_eq!(result.unwrap_err(), NullifierTreeError::InvalidBatchSize);
    assert_eq!(
        tree.batches.first().unwrap().cached_tree_update(0),
        Some(cached)
    );
}
