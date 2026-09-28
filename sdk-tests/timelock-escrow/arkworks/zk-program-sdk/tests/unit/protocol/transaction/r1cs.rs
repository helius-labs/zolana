use super::{
    fixtures::{
        Asserted, Checked, Fund, Payment, Refresh, Settle, LEAVES, NO_TREE, PRIVATE_TX_HASH,
        PUBLIC_HASH, TRANSACTION_HASH,
    },
    labels::{allocated, breaks, checks, tamper, Broken},
    vectors::{forgotten, funds, payments, refreshes, settles},
};
use crate::harness::{
    digest::r1cs_digest,
    fixture::{check_constraints, check_private_variables, size, Size},
};

const PROOF_INPUTS_BREAK_RULE: &str = "ProverError.ProofInputsBreakRule";
const BOOL_RULE: &str = "a bool proof input is neither 0 nor 1";
const U16_RULE: &str = "a u16 proof input does not fit in 16 bits";

const fn inside_scope(scope: &'static str) -> Broken {
    (PROOF_INPUTS_BREAK_RULE, Some(scope), false)
}

fn pinned(constraints: usize, variables: usize, digest: &str) -> (Size, String) {
    (
        Size {
            constraints,
            variables,
        },
        digest.to_string(),
    )
}

#[test]
fn every_shape_has_exactly_the_pinned_size_and_digest() {
    assert_eq!(
        [
            (
                size::<Asserted<Refresh>>(),
                r1cs_digest::<Asserted<Refresh>>()
            ),
            (
                size::<Asserted<Payment>>(),
                r1cs_digest::<Asserted<Payment>>()
            ),
            (size::<Asserted<Fund>>(), r1cs_digest::<Asserted<Fund>>()),
            (
                size::<Asserted<Settle>>(),
                r1cs_digest::<Asserted<Settle>>()
            ),
        ],
        [
            pinned(
                4600,
                4607,
                "294088af2053611f7aa25e4a1a3677ab0df280546d347766c42a39ea5048a2eb"
            ),
            pinned(
                10072,
                10078,
                "a2485a7aeee9d844f2c9a33a52bd07c9b6f092f5b2de4ec79d7652cba8c6e1ea"
            ),
            pinned(
                9321,
                9329,
                "86c3dc9c2758a14cc77f8d7aab996ea687f35fdbe0d2516bcb31873eb7f0e63f"
            ),
            pinned(
                6870,
                6876,
                "18a1c3a2e87c982fde6b94cea046540a30af75766bf06f9534c9a33303a41f8e"
            ),
        ]
    );
}

#[test]
fn every_refresh_and_one_of_each_other_shape_checks_exactly_the_pinned_count() {
    assert_eq!(
        (
            refreshes()
                .into_iter()
                .map(|(name, program)| (name, check_constraints(&Asserted::honest(program))))
                .collect::<Vec<_>>(),
            [
                check_constraints(&Asserted::honest(payments().swap_remove(0).1)),
                check_constraints(&Asserted::honest(funds().swap_remove(0).1)),
                check_constraints(&Asserted::honest(settles().swap_remove(0).1)),
            ],
        ),
        (
            refreshes()
                .into_iter()
                .map(|(name, _)| (name, Ok(4600)))
                .collect::<Vec<_>>(),
            [Ok(10072), Ok(9321), Ok(6870)],
        )
    );
}

#[test]
fn each_tampered_hash_claim_breaks_exactly_its_rule() {
    let fixture = Asserted::honest(refreshes().swap_remove(0).1);
    assert_eq!(
        allocated(&fixture, "a field proof input")
            .into_iter()
            .map(|wire| tamper(&fixture, wire))
            .collect::<Vec<_>>(),
        vec![
            Err(breaks(PRIVATE_TX_HASH)),
            Err(breaks(TRANSACTION_HASH)),
            Err(breaks(PUBLIC_HASH)),
        ]
    );
}

#[test]
fn the_balance_and_tree_rules_own_rows_only_where_a_value_is_variable() {
    let refresh = Asserted::honest(refreshes().swap_remove(0).1);
    let payment = Asserted::honest(payments().swap_remove(0).1);
    let fund = Asserted::honest(funds().swap_remove(0).1);
    let settle = Asserted::honest(settles().swap_remove(0).1);
    assert_eq!(
        (
            [checks(&refresh, LEAVES), checks(&refresh, NO_TREE)],
            [checks(&payment, LEAVES), checks(&payment, NO_TREE)],
            [checks(&fund, LEAVES), checks(&fund, NO_TREE)],
            [checks(&settle, LEAVES), checks(&settle, NO_TREE)],
        ),
        (
            [vec![], vec![2189..2190]],
            [vec![5520..5521], vec![5522..5523]],
            [vec![5516..5517], vec![5518..5519]],
            [vec![], vec![2674..2675]],
        )
    );
}

#[test]
fn only_the_first_nullifier_enters_the_program_circuit_and_the_rest_are_carried() {
    let payment = Asserted::honest(payments().swap_remove(0).1);
    let nullifiers = allocated(&payment, "utxo nullifier");
    let latest_trees = allocated(&payment, "utxo latest tree id");
    assert_eq!(
        (
            nullifiers
                .iter()
                .map(|wire| tamper(&payment, *wire))
                .collect::<Vec<_>>(),
            latest_trees
                .iter()
                .map(|wire| tamper(&payment, *wire))
                .collect::<Vec<_>>(),
        ),
        (
            vec![Err(inside_scope("a poseidon hash")), Ok(()), Ok(())],
            vec![
                Err(inside_scope("the transaction's outputs and hashes")),
                Ok(()),
                Ok(())
            ],
        )
    );
}

#[test]
fn a_tampered_context_breaks_its_range_or_booleanity_row() {
    let payment = Asserted::honest(payments().swap_remove(0).1);
    let from_latest = Asserted::honest(refreshes().swap_remove(2).1);
    let [uses_tree, ..] = allocated(&payment, "a bool proof input")[..] else {
        unreachable!("the context's bool comes first")
    };
    let tree_id = allocated(&payment, "a u16 proof input")[0];
    assert_eq!(
        [
            tamper(&payment, tree_id),
            tamper(&payment, uses_tree),
            tamper(&from_latest, uses_tree),
        ],
        [
            Err(breaks(U16_RULE)),
            Err(breaks(BOOL_RULE)),
            Err(inside_scope("the transaction's outputs and hashes")),
        ]
    );
}

#[test]
fn no_variable_is_free_and_only_carried_spend_values_are_tolerated() {
    let report = |free_and_tolerated: zk_program_sdk::testing::PrivateVariableReport| {
        (
            free_and_tolerated.free.len(),
            free_and_tolerated.tolerated.len(),
        )
    };
    assert_eq!(
        [
            report(check_private_variables(&Asserted::honest(
                refreshes().swap_remove(0).1
            ))),
            report(check_private_variables(&Asserted::honest(
                payments().swap_remove(0).1
            ))),
            report(check_private_variables(&Asserted::honest(
                funds().swap_remove(0).1
            ))),
            report(check_private_variables(&Asserted::honest(
                settles().swap_remove(0).1
            ))),
        ],
        [(0, 0), (0, 7), (0, 2), (0, 0)]
    );
}

#[test]
fn the_prover_refuses_value_that_leaves_the_transaction() {
    assert_eq!(
        check_constraints(&Checked {
            program: forgotten()
        }),
        Err(("CircuitError.RuleBroken", None, None))
    );
}
