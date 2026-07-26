use std::collections::BTreeSet;

use zolana_test_utils::state_model::{
    Action, ExecutionRail, ModelBackend, ModelError, ShieldedPoolBackend,
};

fn funded() -> ModelBackend {
    let mut backend = ModelBackend::new(9);
    backend
        .apply(&Action::Deposit {
            actor: 1,
            asset: 0,
            amount: 100,
        })
        .unwrap();
    backend
}

fn transfer(nonce: u64, rail: ExecutionRail) -> Action {
    Action::Transfer {
        from: 1,
        to: 2,
        asset: 0,
        amount: 1,
        expiry: u64::MAX,
        nonce,
        rail,
    }
}

fn set(values: &[u8]) -> BTreeSet<u8> {
    values.iter().copied().collect()
}

#[test]
fn p256_and_eddsa_owner_rails_have_symmetric_authorization() {
    for (nonce, rail) in [
        ExecutionRail::P256 { owner: 1 },
        ExecutionRail::Eddsa { signer: 1 },
    ]
    .into_iter()
    .enumerate()
    {
        funded().apply(&transfer(nonce as u64, rail)).unwrap();
    }

    for (nonce, rail) in [
        ExecutionRail::P256 { owner: 3 },
        ExecutionRail::Eddsa { signer: 3 },
    ]
    .into_iter()
    .enumerate()
    {
        let mut backend = funded();
        assert_eq!(
            backend.apply(&transfer(nonce as u64, rail)),
            Err(ModelError::Unauthorized)
        );
    }
}

#[test]
fn zone_rail_requires_an_enabled_zone_and_the_utxo_owner() {
    let rail = ExecutionRail::Zone { owner: 1, zone: 4 };
    let mut backend = funded();
    assert_eq!(
        backend.apply(&transfer(1, rail.clone())),
        Err(ModelError::Unauthorized)
    );
    backend
        .apply(&Action::SetZone {
            authority: 9,
            zone: 4,
            enabled: true,
        })
        .unwrap();
    backend.apply(&transfer(1, rail)).unwrap();
}

#[test]
fn smart_account_one_of_one_and_two_of_two_execute() {
    let one_of_one = ExecutionRail::SmartAccount {
        owner: 1,
        members: set(&[5]),
        signatures: set(&[5]),
        threshold: 1,
        execute_after: 0,
    };
    funded().apply(&transfer(1, one_of_one)).unwrap();

    let two_of_two = ExecutionRail::SmartAccount {
        owner: 1,
        members: set(&[5, 6]),
        signatures: set(&[5, 6]),
        threshold: 2,
        execute_after: 0,
    };
    funded().apply(&transfer(2, two_of_two)).unwrap();
}

#[test]
fn smart_account_threshold_counts_only_members() {
    let mut backend = funded();
    let rail = ExecutionRail::SmartAccount {
        owner: 1,
        members: set(&[5, 6]),
        signatures: set(&[5, 99]),
        threshold: 2,
        execute_after: 0,
    };
    assert_eq!(
        backend.apply(&transfer(1, rail)),
        Err(ModelError::InsufficientApprovals)
    );
}

#[test]
fn smart_account_timelock_is_inclusive_at_execute_after() {
    let rail = |execute_after| ExecutionRail::SmartAccount {
        owner: 1,
        members: set(&[5]),
        signatures: set(&[5]),
        threshold: 1,
        execute_after,
    };
    let mut backend = funded();
    assert_eq!(
        backend.apply(&transfer(1, rail(1))),
        Err(ModelError::TimelockActive)
    );
    backend.apply(&Action::AdvanceClock(1)).unwrap();
    backend.apply(&transfer(1, rail(1))).unwrap();
}

#[test]
fn invalid_smart_account_threshold_is_rejected() {
    for threshold in [0, 3] {
        let mut backend = funded();
        let rail = ExecutionRail::SmartAccount {
            owner: 1,
            members: set(&[5, 6]),
            signatures: set(&[5, 6]),
            threshold,
            execute_after: 0,
        };
        assert_eq!(
            backend.apply(&transfer(threshold as u64, rail)),
            Err(ModelError::InvalidThreshold)
        );
    }
}
