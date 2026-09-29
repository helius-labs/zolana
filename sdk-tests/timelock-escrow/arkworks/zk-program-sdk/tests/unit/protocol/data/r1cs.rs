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
                "2b7f467d96fdd6e7c70cf56e9c42a4d24cf0051024554ef6b4fd9455fc096420"
            ),
            pinned(
                2685,
                2692,
                "2b7f467d96fdd6e7c70cf56e9c42a4d24cf0051024554ef6b4fd9455fc096420"
            ),
            pinned(
                1302,
                1304,
                "f519887ab3250f8ef7b2927b1b72985aa85f69773f7ab11ca8752ee9601168a5"
            ),
            pinned(
                4251,
                4257,
                "85b6d6ed91a45e1ec6adc83e6122da8977ea32d69b09f46f26b2ad47122ec5e2"
            ),
            pinned(
                5262,
                5269,
                "298f87ae86c639f6ada6df90a01e1517f8256115c8305476f81481360518cadb"
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
            Ok(5262),
            Ok(4251)
        ]
    );
}
