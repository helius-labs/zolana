use proptest::prelude::*;
use solana_signer::Signer;
use zolana_interface::error::ShieldedPoolError;
use zolana_program_test::ZolanaProgramTest;
use zolana_test_utils::litesvm_asserts::{assert_pool_error, SolDepositOracle, SolDepositSnapshot};

use crate::support::Pool;

#[derive(Clone, Debug)]
enum Action {
    Deposit(u32),
    ZeroDeposit,
    SetPaused(bool),
}

fn action_strategy() -> impl Strategy<Value = Action> {
    prop_oneof![
        7 => (1_000_000u32..=25_000_000).prop_map(Action::Deposit),
        1 => Just(Action::ZeroDeposit),
        2 => any::<bool>().prop_map(Action::SetPaused),
    ]
}

// This is a behavioral state machine, separate from the byte/account mutation
// properties. Its independent ledger predicts accepted and rejected actions,
// then checks all observable balances, roots, leaf ordering, and indexed data
// after every transition.
proptest! {
    #![proptest_config(ProptestConfig {
        cases: 32,
        max_shrink_iters: 2_048,
        ..ProptestConfig::default()
    })]

    #[test]
    fn sol_deposit_lifecycle_matches_the_independent_model(
        actions in prop::collection::vec(action_strategy(), 8..40)
    ) {
        let mut pool = Pool::initialized();
        let depositor = pool.funded_signer(5_000_000_000);
        let tree = pool.tree.pubkey();
        let mut oracle = SolDepositOracle::capture(&pool.rpc, &tree, &depositor.pubkey());
        let mut paused = false;

        for (step, action) in actions.into_iter().enumerate() {
            match action {
                Action::SetPaused(next) => {
                    pool.rpc
                        .pause_tree(&pool.authority, &pool.tree, next)
                        .expect("model pause transition");
                    paused = next;
                }
                Action::Deposit(raw_amount) => {
                    let amount = u64::from(raw_amount);
                    let data = model_deposit_data(step, amount);
                    let before = SolDepositSnapshot::capture(&pool.rpc, &tree, &depositor.pubkey());
                    let result = pool.rpc.deposit(&tree, &depositor, &data);
                    let after = SolDepositSnapshot::capture(&pool.rpc, &tree, &depositor.pubkey());

                    if paused {
                        let error = result.expect_err("paused model deposit must fail");
                        assert_pool_error(error, ShieldedPoolError::TreePaused);
                        before.assert_rejected(&after);
                    } else {
                        let event = result.expect("enabled model deposit must succeed");
                        before.assert_accepted(&after, amount);
                        oracle.record_accepted(&data, &event);
                    }
                }
                Action::ZeroDeposit => {
                    let data = model_deposit_data(step, 0);
                    let before = SolDepositSnapshot::capture(&pool.rpc, &tree, &depositor.pubkey());
                    let error = pool
                        .rpc
                        .deposit(&tree, &depositor, &data)
                        .expect_err("zero model deposit must fail");
                    assert_pool_error(error, ShieldedPoolError::InvalidTransactShape);
                    let after = SolDepositSnapshot::capture(&pool.rpc, &tree, &depositor.pubkey());
                    before.assert_rejected(&after);
                }
            }
            oracle.assert_matches(&pool.rpc, &tree, &depositor.pubkey());
        }
    }
}

fn model_deposit_data(step: usize, amount: u64) -> zolana_interface::instruction::DepositIxData {
    let mut owner = [0u8; 32];
    owner[24..].copy_from_slice(&(step as u64 + 1).to_be_bytes());
    let mut blinding = [0u8; 31];
    blinding[0] = 0x4d;
    blinding[23..].copy_from_slice(&(step as u64 + 1).to_be_bytes());
    let mut data = ZolanaProgramTest::sol_shield_data(amount, owner, blinding);
    data.memo = Some(format!("model-step-{step}").into_bytes());
    data
}
