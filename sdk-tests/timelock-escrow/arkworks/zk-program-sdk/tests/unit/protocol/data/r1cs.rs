use super::{
    fixtures::{
        Burned, Fresh, Held, ASSET, BALANCE, BURN_LEAVES, COMMITS, COUNT, NOT_SPENDABLE, OWNER,
        RING,
    },
    vectors::{burned, holds},
};
use crate::{
    harness::{
        digest::r1cs_digest,
        fixture::{check_constraints, check_private_variables, size, Size},
    },
    protocol::transaction::labels::{allocated, breaks, checks, tamper},
};

#[test]
fn every_data_fixture_has_exactly_the_pinned_size_and_digest_and_a_burn_spends_like_a_mut() {
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
            (size::<Burned<false>>(), r1cs_digest::<Burned<false>>()),
            (size::<Burned<true>>(), r1cs_digest::<Burned<true>>()),
        ],
        [
            pinned(
                2448,
                2455,
                "23a3f8f85446106df6220cfaff4bfafc7f4ad0a3c5b772721c74ec910cc5a211"
            ),
            pinned(
                2448,
                2455,
                "23a3f8f85446106df6220cfaff4bfafc7f4ad0a3c5b772721c74ec910cc5a211"
            ),
            pinned(
                1302,
                1304,
                "f519887ab3250f8ef7b2927b1b72985aa85f69773f7ab11ca8752ee9601168a5"
            ),
            pinned(
                4014,
                4020,
                "da015c2994983e0a8a471a6849842962af4bbfbfd5b71e0aae80bec1c6ac2179"
            ),
            pinned(
                5025,
                5032,
                "d96f0d5388cff2cc3e375621695c798e156f8a88f358fa91049108b5f4c6af51"
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
            .map(|(name, _)| (*name, Ok(2448)))
            .collect::<Vec<_>>()
    );
}

#[test]
fn every_input_rule_owns_its_pinned_rows() {
    let (_, fixture) = &holds()[0];
    assert_eq!(
        (
            [NOT_SPENDABLE, RING, COMMITS].map(|rule| checks(fixture, rule)),
            checks(&burned::<false>(0), BURN_LEAVES),
        ),
        (
            [vec![646..647], vec![647..648, 648..649], vec![862..863]],
            vec![2750..2751],
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
fn the_prover_refuses_a_burned_counter_that_keeps_a_balance() {
    assert_eq!(
        [
            check_constraints(&burned::<false>(300)),
            check_constraints(&burned::<true>(300)),
            check_constraints(&burned::<false>(0)),
        ],
        [
            Err(("CircuitError.RuleBroken", None, None)),
            Ok(5025),
            Ok(4014)
        ]
    );
}
