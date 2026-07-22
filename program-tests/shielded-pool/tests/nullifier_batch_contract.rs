use zolana_test_utils::state_model::{
    Action, ExecutionRail, ModelBackend, ModelError, ShieldedPoolBackend,
};

fn queued(count: u64) -> ModelBackend {
    let mut backend = ModelBackend::new(9);
    for nonce in 0..count {
        backend
            .apply(&Action::Deposit {
                actor: 1,
                asset: 0,
                amount: 10,
            })
            .unwrap();
        backend
            .apply(&Action::Transfer {
                from: 1,
                to: 2,
                asset: 0,
                amount: 10,
                expiry: u64::MAX,
                nonce,
                rail: ExecutionRail::P256 { owner: 1 },
            })
            .unwrap();
    }
    backend
}

#[test]
fn queue_drains_in_order_across_multiple_batches() {
    let mut backend = queued(5);
    let first = backend.state.plan_batch(2).unwrap();
    backend
        .apply(&Action::ExecuteBatch {
            authority: 9,
            plan: first,
        })
        .unwrap();
    let second = backend.state.plan_batch(3).unwrap();
    backend
        .apply(&Action::ExecuteBatch {
            authority: 9,
            plan: second,
        })
        .unwrap();
    assert!(backend.state.queued_nullifiers.is_empty());
    assert_eq!(backend.state.processed_nullifiers, vec![0, 2, 4, 6, 8]);
    assert_eq!(backend.state.batch_generation, 2);
}

#[test]
fn stale_batch_replay_is_rejected_atomically() {
    let mut backend = queued(2);
    let plan = backend.state.plan_batch(1).unwrap();
    backend
        .apply(&Action::ExecuteBatch {
            authority: 9,
            plan: plan.clone(),
        })
        .unwrap();
    let after = backend.snapshot();
    assert_eq!(
        backend.apply(&Action::ExecuteBatch { authority: 9, plan }),
        Err(ModelError::InvalidBatch)
    );
    assert_eq!(backend.state, after);
}

#[test]
fn tampered_or_unauthorized_batch_is_rejected_atomically() {
    let mut backend = queued(3);
    let mut plan = backend.state.plan_batch(2).unwrap();
    plan.nullifiers.swap(0, 1);
    let before = backend.snapshot();
    assert_eq!(
        backend.apply(&Action::ExecuteBatch {
            authority: 9,
            plan: plan.clone(),
        }),
        Err(ModelError::InvalidBatch)
    );
    assert_eq!(backend.state, before);
    assert_eq!(
        backend.apply(&Action::ExecuteBatch { authority: 8, plan }),
        Err(ModelError::Unauthorized)
    );
    assert_eq!(backend.state, before);
}

#[test]
fn batch_is_not_ready_until_the_requested_shape_exists() {
    let backend = queued(1);
    assert_eq!(backend.state.plan_batch(0), Err(ModelError::BatchNotReady));
    assert_eq!(backend.state.plan_batch(2), Err(ModelError::BatchNotReady));
}
