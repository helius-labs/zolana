use zolana_test_utils::state_model::{
    Action, ExecutionRail, ModelBackend, ModelError, ShieldedPoolBackend,
};

fn funded_backend() -> ModelBackend {
    let mut backend = ModelBackend::new(7);
    backend.apply(&Action::AdvanceClock(100)).unwrap();
    backend
        .apply(&Action::Deposit {
            actor: 1,
            asset: 0,
            amount: 50,
        })
        .unwrap();
    backend
}

fn transfer(expiry: u64, nonce: u64) -> Action {
    Action::Transfer {
        from: 1,
        to: 2,
        asset: 0,
        amount: 10,
        expiry,
        nonce,
        rail: ExecutionRail::P256 { owner: 1 },
    }
}

#[test]
fn expiry_is_inclusive_at_the_boundary() {
    let mut backend = funded_backend();
    backend.apply(&transfer(100, 1)).unwrap();
    assert_eq!(backend.state.balance(1, 0), 40);
    assert_eq!(backend.state.balance(2, 0), 10);
}

#[test]
fn expired_transaction_is_atomic() {
    let mut backend = funded_backend();
    let before = backend.snapshot();
    assert_eq!(backend.apply(&transfer(99, 1)), Err(ModelError::Expired));
    assert_eq!(backend.state, before);
}

#[test]
fn successful_nonce_cannot_be_replayed() {
    let mut backend = funded_backend();
    let action = transfer(u64::MAX, 44);
    backend.apply(&action).unwrap();
    let after_first = backend.snapshot();
    assert_eq!(backend.apply(&action), Err(ModelError::Replay));
    assert_eq!(backend.state, after_first);
}

#[test]
fn rejected_nonce_can_be_resubmitted_after_fixing_the_boundary() {
    let mut backend = funded_backend();
    assert_eq!(backend.apply(&transfer(99, 9)), Err(ModelError::Expired));
    backend.apply(&transfer(100, 9)).unwrap();
}

#[test]
fn clock_is_monotonic_and_rollback_preserves_time() {
    let mut backend = funded_backend();
    let before = backend.snapshot();
    assert_eq!(
        backend.apply(&Action::AdvanceClock(99)),
        Err(ModelError::ClockWentBackwards)
    );
    assert_eq!(backend.state, before);
}
