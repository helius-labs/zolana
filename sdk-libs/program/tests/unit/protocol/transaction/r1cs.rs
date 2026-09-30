use super::{
    fixtures::{
        Asserted, Checked, Fund, Payment, Refresh, Settle, LEAVES, NO_TREE, PRIVATE_TX_HASH,
        PUBLIC_HASH, TRANSACTION_HASH,
    },
    labels::{allocated, breaks, checks, scoped, tamper, Broken},
    vectors::{forgotten, funds, payments, refreshes, settles},
};
use crate::harness::{
    digest::r1cs_digest,
    fixture::{check_constraints, check_private_variables, size, Size},
};

const PROOF_INPUTS_BREAK_RULE: &str = "ProverError.ProofInputsBreakRule";
const BOOL_RULE: &str = "a bool proof input is neither 0 nor 1";
const U16_RULE: &str = "a u16 proof input does not fit in 16 bits";
const EMPTINESS: &str = "whether a token output is empty";

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
                4134,
                4141,
                "6f2163aebd862460a90ef116f9f4e296fe6bec637341eeda0d7089ba7630b17f"
            ),
            pinned(
                9624,
                9630,
                "1028f19947cb85698821c398427abf950b6f5de9ad72ecaad56fe8ea83c5d078"
            ),
            pinned(
                8853,
                8861,
                "b39689a8c508993c6640562a93fef2aa4a3b4c3a25582a4f9b9e1a0d3f4d86af"
            ),
            pinned(
                6404,
                6410,
                "25045c893c9fae7b9b34c25d9e1059e467502068754c35565ae871bdc9be957f"
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
                .map(|(name, _)| (name, Ok(4134)))
                .collect::<Vec<_>>(),
            [Ok(9624), Ok(8853), Ok(6404)],
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
fn a_prover_cannot_flip_whether_a_token_output_is_empty_and_only_a_zero_amounts_hint_is_free() {
    let [(_, kept), (_, emptied), _] = <[_; 3]>::try_from(payments()).expect("three payments");
    let tampered = |program| {
        let fixture = Asserted::honest(program);
        scoped(&fixture, EMPTINESS)
            .into_iter()
            .map(|wire| tamper(&fixture, wire))
            .collect::<Vec<_>>()
    };
    let refused = Err(inside_scope("an equality test"));
    assert_eq!(
        (tampered(kept), tampered(emptied)),
        (
            vec![refused, refused, refused, refused],
            vec![refused, refused, refused, Ok(())],
        )
    );
}

#[test]
fn no_variable_is_free_and_only_carried_spend_values_are_tolerated() {
    let report = |free_and_tolerated: zolana_program::testing::PrivateVariableReport| {
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
