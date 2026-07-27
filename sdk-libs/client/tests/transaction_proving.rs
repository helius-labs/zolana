//! Transfer proof matrix for the fixed (2,3) circuit shape.

mod harness;
mod prover;
mod prover_bootstrap;
mod proving;
mod test_indexer;

use harness::{Asset, InputSpec, Owner, SendSpec, TransferHarness, TransferPlan, WithdrawSpec};

// NOTE(pr164): the P256-owner and mixed-owner proof matrices were removed:
// PR164 removed the P256 transact rail (`P256TransactUnsupported`), so no
// P256-owned input can produce a transfer proof anymore.
use std::{any::Any, panic::AssertUnwindSafe};

type SingleOwnerCase = (
    Vec<(Asset, u64)>,
    Vec<(Asset, u64)>,
    Option<(Asset, u64)>,
    bool,
);

fn run(
    inputs: &[(Owner, Asset, u64)],
    sends: &[(Asset, u64)],
    withdraw: Option<(Asset, u64)>,
    declared_shape: bool,
) {
    TransferHarness {
        plan: TransferPlan {
            inputs: inputs
                .iter()
                .map(|&(owner, asset, amount)| InputSpec {
                    owner,
                    asset,
                    amount,
                })
                .collect(),
            sends: sends
                .iter()
                .map(|&(asset, amount)| SendSpec { asset, amount })
                .collect(),
            withdraw: withdraw.map(|(asset, amount)| WithdrawSpec { asset, amount }),
            declared_shape,
        },
    }
    .prove_and_verify();
}

fn panic_message(payload: &(dyn Any + Send)) -> &str {
    payload
        .downcast_ref::<String>()
        .map(String::as_str)
        .or_else(|| payload.downcast_ref::<&str>().copied())
        .unwrap_or("non-string panic payload")
}

fn run_with_context(
    case_index: usize,
    inputs: &[(Owner, Asset, u64)],
    sends: &[(Asset, u64)],
    withdraw: Option<(Asset, u64)>,
    declared_shape: bool,
) {
    let result = std::panic::catch_unwind(AssertUnwindSafe(|| {
        run(inputs, sends, withdraw, declared_shape)
    }));
    if let Err(payload) = result {
        panic!(
            "proof case {case_index} failed: inputs={inputs:?}, sends={sends:?}, \
             withdraw={withdraw:?}, declared_shape={declared_shape}: {}",
            panic_message(payload.as_ref())
        );
    }
}

fn run_single_owner_matrix(owner: Owner) {
    use Asset::{Sol, Spl};
    let cases: Vec<SingleOwnerCase> = vec![
        (vec![(Sol, 100)], vec![(Sol, 60)], None, false),
        (vec![(Sol, 100), (Sol, 50)], vec![(Sol, 60)], None, false),
        (vec![(Sol, 100)], vec![(Sol, 100)], None, false),
        (vec![(Sol, 100)], vec![], None, false),
        (vec![(Sol, 100), (Sol, 50)], vec![], None, false),
        (vec![(Sol, 100)], vec![], Some((Sol, 30)), false),
        (vec![(Sol, 100)], vec![(Sol, 70)], Some((Sol, 30)), false),
        (vec![(Sol, 100)], vec![(Sol, 40)], Some((Sol, 30)), false),
        (vec![(Sol, 100)], vec![], Some((Sol, 100)), false),
        (vec![(Sol, 100), (Sol, 50)], vec![], Some((Sol, 30)), false),
        (vec![(Spl, 100)], vec![(Spl, 60)], None, false),
        (vec![(Spl, 100)], vec![(Spl, 100)], None, false),
        (vec![(Spl, 100), (Spl, 50)], vec![], None, false),
        (vec![(Spl, 100)], vec![], Some((Spl, 30)), false),
        (vec![(Spl, 100)], vec![], Some((Spl, 100)), false),
        (vec![(Spl, 100)], vec![(Spl, 40)], Some((Spl, 30)), false),
        (vec![(Sol, 100), (Spl, 100)], vec![(Spl, 60)], None, false),
        (vec![(Sol, 100), (Spl, 100)], vec![], None, false),
        (
            vec![(Sol, 100), (Spl, 100)],
            vec![(Spl, 60)],
            Some((Sol, 100)),
            false,
        ),
        (
            vec![(Sol, 100), (Spl, 100)],
            vec![(Sol, 60)],
            Some((Spl, 100)),
            false,
        ),
        (vec![(Sol, 100)], vec![(Sol, 60)], None, true),
    ];
    for (case_index, (inputs, sends, withdraw, declared)) in cases.into_iter().enumerate() {
        let inputs: Vec<_> = inputs
            .into_iter()
            .map(|(asset, amount)| (owner, asset, amount))
            .collect();
        run_with_context(case_index, &inputs, &sends, withdraw, declared);
    }
}

#[test]
#[serial_test::serial]
fn solana_owner_public_amount_and_output_matrix_proves() {
    run_single_owner_matrix(Owner::Solana);
}

