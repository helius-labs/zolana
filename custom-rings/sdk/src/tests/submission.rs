use custom_ring_interface::RingMode;
use zolana_interface::pda;

use super::*;
use crate::tests::support::{ring, Chain, Registry, RingSettings, SLOT, TREE_ID};

#[tokio::test]
async fn a_policy_write_an_overwritten_root_or_a_passed_epoch_moves_the_proof() {
    let chain = Chain::ring(RingSettings {
        has_policy: true,
        ..RingSettings::new(RingMode::Registry)
    })
    .with_registry(Registry::new(&[]), &crate::tests::pipeline_rules());
    let pinned = ring().require_registry(&chain).await.unwrap().policy_hash;
    let policy = |hash| BoundState {
        policy: Some(BoundPolicy { ring: ring(), hash }),
        ..BoundState::default()
    };
    assert!(!policy(pinned).moved(&chain).await.unwrap());
    assert!(policy([1; 32]).moved(&chain).await.unwrap());
    let tree = pda::tree(TREE_ID);
    let root = chain
        .get_merkle_proofs(tree, vec![[0; 32]], None)
        .await
        .unwrap()
        .proofs[0]
        .root;
    let anchor = |root| BoundState {
        anchor: Some(BoundAnchor {
            tree,
            root_index: 0,
            root,
        }),
        ..BoundState::default()
    };
    assert!(!anchor(root).moved(&chain).await.unwrap());
    assert!(anchor([1; 32]).moved(&chain).await.unwrap());
    let epoch = |epoch| BoundState {
        epoch: Some(epoch),
        ..BoundState::default()
    };
    assert!(!epoch(tag_epoch(SLOT)).moved(&chain).await.unwrap());
    assert!(epoch(tag_epoch(SLOT) - 1).moved(&chain).await.unwrap());
}

#[tokio::test]
async fn a_fresh_proof_fixes_a_stale_root_and_an_expired_blockhash_alone() {
    let chain = Chain::ring(RingSettings::new(RingMode::Off));
    let ring_failure = |error: CustomRingError| {
        TransactionError::InstructionError(0, InstructionError::Custom(error as u32))
    };
    let unmoved = BoundState::default();
    for (error, fixed) in [
        (TransactionError::BlockhashNotFound, true),
        (ring_failure(CustomRingError::RootBelowFloor), true),
        (ring_failure(CustomRingError::AuthorityBatchTooLarge), true),
        (
            ring_failure(CustomRingError::ProofVerificationFailed),
            false,
        ),
        (ring_failure(CustomRingError::QueueFull), false),
        (TransactionError::AccountNotFound, false),
    ] {
        assert_eq!(
            unmoved.reproof_fixes(&error, &chain).await.unwrap(),
            fixed,
            "{error:?}"
        );
    }
}
