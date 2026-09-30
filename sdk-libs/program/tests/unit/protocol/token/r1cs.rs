use super::{
    fixtures::{
        Spend, ASSET, AS_GIVEN, BALANCE, BALANCE_FITS, DIFFERENT_ASSETS, DIFFERENT_OWNERS,
        FIRST_DUMMY, KEYED_DUMMY, NOT_SPENDABLE, OWNER, PROGRAM_STATE, RING,
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
                    constraints: 2173,
                    variables: 2180
                },
                "74ef4030a4ef4495f12f25331a1aa2fe81840904a57186ad9ac0d85ca26303a3".to_string()
            ),
            (
                Size {
                    constraints: 3694,
                    variables: 3700
                },
                "ec84a61b9f39e4e9b43ba0b1ce9afdb0ff6b1e0af55364a94ce008aef30b11c6".to_string()
            ),
            (
                Size {
                    constraints: 5150,
                    variables: 5156
                },
                "2471e631e07149e0d2f8eb2106ada0ca897f7d6869ff8a0ef4cb09ba37c67df3".to_string()
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
            pinned(ones(), 2173),
            pinned(twos(), 3694),
            pinned(threes(), 5150)
        )
    );
}

#[test]
fn every_input_rule_owns_rows_for_every_input_it_applies_to() {
    let (_, two) = &twos()[0];
    let (_, three) = &threes()[0];
    let rules = [
        FIRST_DUMMY,
        RING,
        PROGRAM_STATE,
        NOT_SPENDABLE,
        DIFFERENT_ASSETS,
        DIFFERENT_OWNERS,
        KEYED_DUMMY,
    ];
    assert_eq!(
        (
            rules.map(|rule| checks(two, rule)),
            rules.map(|rule| checks(three, rule).len()),
        ),
        (
            [
                vec![1162..1163],
                vec![1885..1886, 1886..1887, 2753..2754, 2754..2755],
                vec![1887..1888, 2755..2756],
                vec![2756..2757],
                vec![2757..2758, 2758..2759],
                vec![2759..2760, 2760..2761, 2761..2762],
                vec![2762..2763],
            ],
            [1, 6, 3, 2, 4, 6, 2],
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
        (vec![Ok(()); 2], (0, 4), (0, 6), 1)
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
    assert_eq!(ranges.len(), 2, "two packed components of a mint");
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
        let [(left_coefficient, left), (right_coefficient, right)] = a.as_slice() else {
            panic!("the equality row must contain exactly two operands: {a:?}");
        };
        let [(enabled_coefficient, enabled)] = b.as_slice() else {
            panic!("the condition must be one outlined enable variable: {b:?}");
        };
        assert_eq!(
            (
                *left_coefficient,
                *right_coefficient,
                *enabled_coefficient,
                c
            ),
            (-Fr::one(), Fr::one(), Fr::one(), &vec![]),
        );
        let (_, with_dummy) = fixtures.get(1).expect("real and dummy inputs");
        assert_eq!(
            (
                honest.get(*enabled).copied(),
                assignment(with_dummy).get(*enabled).copied()
            ),
            (Some(Fr::one()), Some(Fr::zero())),
        );
        assert_ne!(left, right);
        assert_ne!(left, enabled);
        assert_ne!(right, enabled);
        for l in [Fr::zero(), Fr::one(), -Fr::one(), Fr::from(u64::MAX)] {
            for r in [Fr::zero(), Fr::one(), -Fr::one(), Fr::from(u64::MAX)] {
                for skip_value in [false, true] {
                    let mut witness = honest.clone();
                    *witness.get_mut(*left).expect("left component") = l;
                    *witness.get_mut(*right).expect("right component") = r;
                    *witness.get_mut(*enabled).expect("enable flag") =
                        Fr::from(u64::from(!skip_value));
                    assert_eq!(
                        evaluate(a, &witness) * evaluate(b, &witness) == evaluate(c, &witness),
                        skip_value || l == r,
                    );
                }
            }
        }
    }
}
