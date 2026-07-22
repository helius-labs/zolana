use zolana_test_utils::state_model::{Action, ExecutionRail, ModelBackend, ShieldedPoolBackend};

#[test]
fn existing_utxos_survive_authority_and_registry_rotation() {
    let mut backend = ModelBackend::new(1);
    backend
        .apply(&Action::Deposit {
            actor: 7,
            asset: 2,
            amount: 100,
        })
        .unwrap();
    let original_utxo = backend.state.utxos[0].clone();

    backend
        .apply(&Action::RotateRegistry { authority: 1 })
        .unwrap();
    backend
        .apply(&Action::RotateAuthority {
            authority: 1,
            next: 2,
        })
        .unwrap();
    backend
        .apply(&Action::RotateRegistry { authority: 2 })
        .unwrap();

    assert_eq!(original_utxo.registry_version, 0);
    assert_eq!(backend.state.registry_version, 2);
    backend
        .apply(&Action::Transfer {
            from: 7,
            to: 8,
            asset: 2,
            amount: 60,
            expiry: u64::MAX,
            nonce: 1,
            rail: ExecutionRail::P256 { owner: 7 },
        })
        .unwrap();
    assert_eq!(backend.state.balance(7, 2), 40);
    assert_eq!(backend.state.balance(8, 2), 60);
}

#[test]
fn replaying_a_committed_regression_script_is_deterministic() {
    let actions = vec![
        Action::Deposit {
            actor: 1,
            asset: 0,
            amount: 11,
        },
        Action::RotateRegistry { authority: 4 }, // intentional rejection
        Action::SetMergePermission {
            authority: 3,
            actor: 1,
            enabled: true,
        },
        Action::Consolidate {
            actor: 1,
            asset: 0,
            max_inputs: 8,
            expiry: u64::MAX,
            nonce: 77,
            rail: ExecutionRail::Eddsa { signer: 1 },
        },
    ];
    let first = ModelBackend::replay(3, &actions);
    let second = ModelBackend::replay(3, &actions);
    assert_eq!(first.state, second.state);
    assert_eq!(first.journal, second.journal);
    assert_eq!(first.journal.len(), actions.len());
}

#[test]
fn new_authority_exclusively_controls_future_policy_changes() {
    let mut backend = ModelBackend::new(1);
    backend
        .apply(&Action::RotateAuthority {
            authority: 1,
            next: 2,
        })
        .unwrap();
    let before = backend.snapshot();
    assert!(backend
        .apply(&Action::SetPaused {
            authority: 1,
            paused: true,
        })
        .is_err());
    assert_eq!(backend.state, before);
    backend
        .apply(&Action::SetPaused {
            authority: 2,
            paused: true,
        })
        .unwrap();
}
