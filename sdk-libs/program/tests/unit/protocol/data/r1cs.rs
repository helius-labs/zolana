use super::{
    fixtures::{
        Closed, Fresh, Held, ASSET, BALANCE, CLOSE_LEAVES, COMMITS, COUNT, NOT_SPENDABLE, OWNER,
        RING,
    },
    vectors::{closed, holds},
};
use crate::{
    harness::{
        digest::r1cs_digest,
        fixture::{check_constraints, check_private_variables, size, Size},
    },
    protocol::transaction::labels::{allocated, breaks, checks, tamper},
};

#[test]
fn every_data_fixture_has_exactly_the_pinned_size_and_digest_and_a_close_spends_like_a_mut() {
    let pinned = |constraints, variables, digest: &str| {
        (
            Size {
                constraints,
                variables,
            },
            digest.to_string(),
        )
    };
    assert_eq!(
        [
            (size::<Held<false>>(), r1cs_digest::<Held<false>>()),
            (size::<Held<true>>(), r1cs_digest::<Held<true>>()),
            (size::<Fresh>(), r1cs_digest::<Fresh>()),
            (size::<Closed<false>>(), r1cs_digest::<Closed<false>>()),
            (size::<Closed<true>>(), r1cs_digest::<Closed<true>>()),
        ],
        [
            pinned(
                2684,
                2691,
                "a9a9009892f3bd66603dabba7ec6554f9727fde6659af3ce88d6caafe75b0f04"
            ),
            pinned(
                2684,
                2691,
                "a9a9009892f3bd66603dabba7ec6554f9727fde6659af3ce88d6caafe75b0f04"
            ),
            pinned(
                1301,
                1303,
                "551c00cfe4eca1305ce56a957140eca1b121cd6712c79f90e771de0105ff8973"
            ),
            pinned(
                4013,
                4019,
                "b6a1f0cbbdba3424d52e9e14a54fac1aa28e5d5113c0d5887a9efa37ba95493a"
            ),
            pinned(
                5024,
                5031,
                "ccdfdd72ece24af1987d59dc3cba71487073ffbcb6745697079963487fb0c634"
            ),
        ]
    );
}

#[test]
fn every_held_counter_checks_exactly_the_pinned_count() {
    assert_eq!(
        holds()
            .iter()
            .map(|(name, fixture)| (*name, check_constraints(fixture)))
            .collect::<Vec<_>>(),
        holds()
            .iter()
            .map(|(name, _)| (*name, Ok(2684)))
            .collect::<Vec<_>>()
    );
}

#[test]
fn every_input_rule_owns_its_pinned_rows() {
    let (_, fixture) = &holds()[0];
    assert_eq!(
        (
            [NOT_SPENDABLE, RING, COMMITS].map(|rule| checks(fixture, rule)),
            checks(&closed::<false>(0), CLOSE_LEAVES),
        ),
        (
            [vec![645..646], vec![646..647, 647..648], vec![1098..1099]],
            vec![2986..2987],
        )
    );
}

#[test]
fn a_tampered_claim_or_data_hash_breaks_exactly_its_rule() {
    let (_, fixture) = &holds()[0];
    let claims = allocated(fixture, "a field proof input");
    let data_hash = allocated(fixture, "utxo data hash")[0];
    assert_eq!(
        (
            claims
                .iter()
                .map(|wire| tamper(fixture, *wire))
                .collect::<Vec<_>>(),
            tamper(fixture, data_hash),
        ),
        (
            vec![
                Err(breaks(COUNT)),
                Err(breaks(BALANCE)),
                Err(breaks(OWNER)),
                Err(breaks(ASSET))
            ],
            Err(breaks(COMMITS)),
        )
    );
}

#[test]
fn only_the_carried_nullifier_and_latest_tree_are_tolerated() {
    let (_, fixture) = &holds()[0];
    let report = check_private_variables(fixture);
    assert_eq!((report.free.len(), report.tolerated.len()), (0, 2));
}

#[test]
fn the_prover_refuses_a_closed_counter_that_keeps_a_balance() {
    assert_eq!(
        [
            check_constraints(&closed::<false>(300)),
            check_constraints(&closed::<true>(300)),
            check_constraints(&closed::<false>(0)),
        ],
        [
            Err(("CircuitError.RuleBroken", None, None)),
            Ok(5024),
            Ok(4013)
        ]
    );
}
