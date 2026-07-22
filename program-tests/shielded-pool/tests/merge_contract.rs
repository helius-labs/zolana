use zolana_test_utils::state_model::{
    Action, ExecutionRail, ModelBackend, ModelError, ShieldedPoolBackend,
};

#[test]
fn merge_covers_every_supported_input_count() {
    for count in 1usize..=8 {
        let mut backend = ModelBackend::new(9);
        backend
            .apply(&Action::SetMergePermission {
                authority: 9,
                actor: 1,
                enabled: true,
            })
            .unwrap();
        for amount in 1..=count as u64 {
            backend
                .apply(&Action::Deposit {
                    actor: 1,
                    asset: 0,
                    amount,
                })
                .unwrap();
        }
        let expected: u64 = (1..=count as u64).sum();
        backend
            .apply(&Action::Consolidate {
                actor: 1,
                asset: 0,
                max_inputs: count,
                expiry: u64::MAX,
                nonce: count as u64,
                rail: ExecutionRail::P256 { owner: 1 },
            })
            .unwrap();
        assert_eq!(backend.state.balance(1, 0), expected);
        assert_eq!(backend.state.spendable_utxos(1, 0), 1);
    }
}

#[test]
fn merge_requires_opt_in_and_rolls_back_on_rejection() {
    let mut backend = ModelBackend::new(9);
    backend
        .apply(&Action::Deposit {
            actor: 1,
            asset: 0,
            amount: 10,
        })
        .unwrap();
    let before = backend.snapshot();
    assert_eq!(
        backend.apply(&Action::Consolidate {
            actor: 1,
            asset: 0,
            max_inputs: 8,
            expiry: u64::MAX,
            nonce: 1,
            rail: ExecutionRail::Eddsa { signer: 1 },
        }),
        Err(ModelError::MergeDisabled)
    );
    assert_eq!(backend.state, before);
}
