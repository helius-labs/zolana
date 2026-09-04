use proptest::prelude::*;
use solana_signer::Signer;
use zolana_interface::error::ShieldedPoolError;
use zolana_program_test::{Rejection, ZolanaProgramTest};
use zolana_test_utils::litesvm_asserts::{SolDepositOracle, SolDepositSnapshot};

use shielded_pool_tests::support::fixtures::Pool;

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
        let tree = pool.tree;
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
                deposit @ (Action::Deposit(_) | Action::ZeroDeposit) => {
                    // PR164 dropped the zero-amount gate: while the tree is
                    // unpaused a zero deposit is accepted, appends an empty
                    // output, and settles nothing.
                    let (amount, noun) = match deposit {
                        Action::Deposit(raw) => (u64::from(raw), "deposit"),
                        Action::ZeroDeposit => (0, "zero deposit"),
                        Action::SetPaused(_) => unreachable!("covered by the outer arm"),
                    };
                    let data = model_deposit_data(step, amount);
                    let before = SolDepositSnapshot::capture(&pool.rpc, &tree, &depositor.pubkey());
                    let result = pool.rpc.deposit(&tree, &depositor, &data);
                    let after = SolDepositSnapshot::capture(&pool.rpc, &tree, &depositor.pubkey());

                    if paused {
                        let error = match result {
                            Err(error) => error,
                            Ok(meta) => panic!("paused model {noun} must fail: {meta:?}"),
                        };
                        Rejection::pool(ShieldedPoolError::TreePaused).assert_litesvm(error);
                        before.assert_rejected(&after);
                    } else {
                        let event = match result {
                            Ok(event) => event,
                            Err(err) => panic!("enabled model {noun} must succeed: {err:?}"),
                        };
                        before.assert_accepted(&after, amount);
                        oracle.record_accepted(&data, &event);
                    }
                }
            }
            oracle.assert_matches(&pool.rpc, &tree, &depositor.pubkey());
        }
    }
}

fn model_deposit_data(step: usize, amount: u64) -> zolana_interface::instruction::AssetDeposit {
    let mut owner = [0u8; 32];
    owner[24..].copy_from_slice(&(step as u64 + 1).to_be_bytes());
    let mut blinding = [0u8; 32];
    blinding[1] = 0x4d;
    blinding[24..].copy_from_slice(&(step as u64 + 1).to_be_bytes());
    let mut data = ZolanaProgramTest::sol_shield_data(amount, owner, blinding);
    data.memo = Some(format!("model-step-{step}").into_bytes());
    data
}
