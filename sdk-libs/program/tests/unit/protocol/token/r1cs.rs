use super::{
    fixtures::{
        Spend, ASSET, AS_GIVEN, BALANCE, BALANCE_FITS, DIFFERENT_ASSETS, DIFFERENT_OWNERS,
        NOT_SPENDABLE, OWNER, PROGRAM_STATE, RING,
    },
    vectors::{ones, threes, twos, Named},
};
use crate::{
    harness::{
        digest::r1cs_digest,
        fixture::{check_constraints, check_private_variables, size, ProverRefusal, Size},
    },
    protocol::transaction::labels::{allocated, breaks, checks, tamper, Broken},
};

const PROOF_INPUTS_BREAK_RULE: &str = "ProverError.ProofInputsBreakRule";

const fn inside_scope(scope: &'static str) -> Broken {
    (PROOF_INPUTS_BREAK_RULE, Some(scope), false)
}

#[test]
fn every_spend_width_has_exactly_the_pinned_size_and_digest() {
    assert_eq!(
        [
            (
                size::<Spend<1, AS_GIVEN>>(),
                r1cs_digest::<Spend<1, AS_GIVEN>>()
            ),
            (
                size::<Spend<2, AS_GIVEN>>(),
                r1cs_digest::<Spend<2, AS_GIVEN>>()
            ),
            (
                size::<Spend<3, AS_GIVEN>>(),
                r1cs_digest::<Spend<3, AS_GIVEN>>()
            ),
        ],
        [
            (
                Size {
                    constraints: 2177,
                    variables: 2179
                },
                "141775d9adcfbc848f72e90e95447efe092e8327af14baa34c3630c401e61572".to_string()
            ),
            (
                Size {
                    constraints: 3764,
                    variables: 3766
                },
                "3624041d4ccaf7b438da268e6bd1751bf9daeb6c8df1f836a04fdde86bc07e1a".to_string()
            ),
            (
                Size {
                    constraints: 5286,
                    variables: 5289
                },
                "8aa7a3d3f66a5cb1e2b746aab7382a3d0416ba98530ae933030d22763cbb5ec3".to_string()
            ),
        ]
    );
}

type Checked = Vec<(&'static str, Result<usize, ProverRefusal>)>;

fn checked<const N: usize>(named: Named<Spend<N, AS_GIVEN>>) -> Checked {
    named
        .into_iter()
        .map(|(name, fixture)| (name, check_constraints(&fixture)))
        .collect()
}

fn pinned<const N: usize>(named: Named<Spend<N, AS_GIVEN>>, count: usize) -> Checked {
    named
        .into_iter()
        .map(|(name, _)| (name, Ok(count)))
        .collect()
}

#[test]
fn every_honest_spend_checks_exactly_the_pinned_count() {
    assert_eq!(
        (checked(ones()), checked(twos()), checked(threes())),
        (
            pinned(ones(), 2177),
            pinned(twos(), 3764),
            pinned(threes(), 5286)
        )
    );
}

#[test]
fn every_input_rule_owns_rows_for_every_input_it_applies_to() {
    let (_, two) = &twos()[0];
    let (_, three) = &threes()[0];
    let rules = [
        RING,
        PROGRAM_STATE,
        NOT_SPENDABLE,
        DIFFERENT_ASSETS,
        DIFFERENT_OWNERS,
    ];
    assert_eq!(
        (
            rules.map(|rule| checks(two, rule)),
            rules.map(|rule| checks(three, rule).len()),
        ),
        (
            [
                vec![1163..1164, 1164..1165, 1170..1171, 1171..1172],
                vec![1165..1166, 1172..1173],
                vec![1162..1163, 1169..1170],
                vec![1962..1963, 1963..1964, 2829..2830, 2830..2831],
                vec![
                    1964..1965,
                    1965..1966,
                    1966..1967,
                    2831..2832,
                    2832..2833,
                    2833..2834
                ],
            ],
            [6, 3, 3, 6, 9],
        )
    );
}

#[test]
fn a_tampered_claim_breaks_exactly_its_rule() {
    let (_, fixture) = &twos()[0];
    let claims = allocated(fixture, "a field proof input");
    assert_eq!(
        claims
            .iter()
            .map(|wire| tamper(fixture, *wire))
            .collect::<Vec<_>>(),
        vec![Err(breaks(BALANCE)), Err(breaks(OWNER)), Err(breaks(ASSET))]
    );
}

#[test]
fn a_tampered_amount_or_blinding_breaks_the_input_hash_and_a_dummys_amount_its_select() {
    let (_, real) = &twos()[0];
    let (_, with_dummy) = &twos()[1];
    let amounts = allocated(real, "utxo amount");
    let blindings = allocated(real, "utxo blinding");
    let dummy_amount = allocated(with_dummy, "utxo amount")[1];
    assert_eq!(
        (
            amounts
                .iter()
                .map(|wire| tamper(real, *wire))
                .collect::<Vec<_>>(),
            blindings
                .iter()
                .map(|wire| tamper(real, *wire))
                .collect::<Vec<_>>(),
            tamper(with_dummy, dummy_amount),
        ),
        (
            vec![Err(inside_scope("a poseidon hash")); 2],
            vec![Err(inside_scope("a poseidon hash")); 2],
            Err(inside_scope("a token utxo's inputs")),
        )
    );
}

#[test]
fn the_carried_nullifiers_are_tolerated_and_no_other_variable_is_free() {
    let (_, real) = &twos()[0];
    let (_, with_dummy) = &twos()[1];
    let nullifiers = allocated(real, "utxo nullifier");
    let report = |fixture: &Spend<2, AS_GIVEN>| {
        let report = check_private_variables(fixture);
        (report.free.len(), report.tolerated.len())
    };
    assert_eq!(
        (
            nullifiers
                .iter()
                .map(|wire| tamper(real, *wire))
                .collect::<Vec<_>>(),
            report(real),
            report(with_dummy),
            checks(real, BALANCE_FITS).len(),
        ),
        (vec![Ok(()); 2], (0, 4), (0, 8), 1)
    );
}

#[test]
fn variable_skip_row_binds_the_trailing_asset_byte_exactly_when_the_input_is_not_dummy() {
    use ark_bn254::Fr;
    use ark_ff::{One, Zero};

    use crate::harness::{
        fixture::{assignment, exported},
        iden3::Row,
    };

    let fixtures = twos();
    let (_, fixture) = fixtures.first().expect("two real inputs");
    let rows = exported::<Spend<2, AS_GIVEN>>();
    let ranges = checks(fixture, DIFFERENT_ASSETS);
    assert_eq!(
        ranges.len(),
        4,
        "two packed components checked for each real input"
    );
    let evaluate = |row: &Row, witness: &[Fr]| {
        row.iter().fold(Fr::zero(), |sum, (coefficient, wire)| {
            sum + coefficient * witness.get(*wire).expect("row wire")
        })
    };
    let honest = assignment(fixture);
    {
        let range = ranges.last().expect("trailing byte equality");
        assert_eq!(
            range.len(),
            1,
            "one conditional equality for the trailing byte"
        );
        let (a, b, c) = rows.rows().nth(range.start).expect("asset equality row");
        let (coefficient, wire) = a
            .iter()
            .find(|(_, wire)| *wire != 0)
            .expect("an asset component");
        let [(enabled_coefficient, enabled)] = b.as_slice() else {
            panic!("the condition must be one outlined enable variable: {b:?}");
        };
        assert_eq!((*enabled_coefficient, c), (Fr::one(), &vec![]));
        assert_ne!(*coefficient, Fr::zero());
        let (_, with_dummy) = fixtures.get(1).expect("real and dummy inputs");
        assert_eq!(
            (
                honest.get(*enabled).copied(),
                assignment(with_dummy).get(*enabled).copied()
            ),
            (Some(Fr::one()), Some(Fr::zero())),
        );
        assert_ne!(wire, enabled);
        for delta in [Fr::zero(), Fr::one(), -Fr::one(), Fr::from(u64::MAX)] {
            for skip_value in [false, true] {
                let mut witness = honest.clone();
                *witness.get_mut(*wire).expect("asset component") += delta;
                *witness.get_mut(*enabled).expect("enable flag") = Fr::from(u64::from(!skip_value));
                assert_eq!(
                    evaluate(a, &witness) * evaluate(b, &witness) == evaluate(c, &witness),
                    skip_value || delta.is_zero(),
                    "the asset equality is enforced exactly when the input is real"
                );
            }
        }
    }
}
