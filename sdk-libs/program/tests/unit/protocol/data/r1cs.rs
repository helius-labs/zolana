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
                2685,
                2692,
                "b4c2501ee60122909ad2d1b6bcc893bda1245a2cb694ab893b27ec18d744f93b"
            ),
            pinned(
                2685,
                2692,
                "b4c2501ee60122909ad2d1b6bcc893bda1245a2cb694ab893b27ec18d744f93b"
            ),
            pinned(
                1302,
                1304,
                "f519887ab3250f8ef7b2927b1b72985aa85f69773f7ab11ca8752ee9601168a5"
            ),
            pinned(
                4014,
                4020,
                "16d1ac89228ef94b99ca782ad63c8edc5760f65767d5b3cd32d02c358b8109d5"
            ),
            pinned(
                5025,
                5032,
                "084b523a2a0e92cdabbce3a49fdcba12495e46376d1dfcd748ca80c956bb5a48"
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
            .map(|(name, _)| (*name, Ok(2685)))
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
            [vec![646..647], vec![647..648, 648..649], vec![1099..1100]],
            vec![2987..2988],
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
            Ok(5025),
            Ok(4014)
        ]
    );
}
