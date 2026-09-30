use super::fixtures::*;
use crate::{
    harness::{
        digest::r1cs_digest,
        fixture::{
            assignment, check_constraints, check_private_variables, check_tampered, exported,
            native, size, with_wires,
        },
    },
    uint::rows::{decomposition, golden, linear, power_of_two, rows},
};
use ark_bn254::Fr;
use ark_ff::One;
use zolana_program::{circuit::Field, ZkCircuit};

pub fn honest<F: ZkCircuit>(fixture: &F) {
    assert_eq!(native(fixture), Ok(()));
    assert_eq!(check_constraints(fixture), Ok(size::<F>().constraints));
    assert_eq!(
        exported::<F>().first_unsatisfied(&assignment(fixture)),
        None
    );
}

fn sound<F: ZkCircuit>(fixture: &F, claims: &[usize]) {
    honest(fixture);
    let witness = assignment(fixture);
    for wire in claims {
        let wrong = *witness.get(*wire).expect("claimed wire") + Fr::one();
        let refusal = check_tampered(fixture, *wire, Field::from(wrong))
            .expect_err("a false claim is refused");
        assert_eq!(
            (refusal.0, refusal.2),
            ("ProverError.ProofInputsBreakRule", Some(CLAIM))
        );
        assert!(exported::<F>()
            .first_unsatisfied(&with_wires(witness.clone(), &[(*wire, wrong)]))
            .is_some());
    }
    let report = check_private_variables(fixture);
    assert!(report.free.is_empty(), "unbound wires: {:?}", report.free);
}

fn compare_all<const OP: u8>() {
    for x in 0..16u128 {
        for y in 0..16u128 {
            honest(&compare::<4, OP>(x, y));
        }
    }
    sound(&compare::<4, OP>(5, 9), &[3]);
    sound(&compare::<4, OP>(5, 5), &[3]);
}

#[test]
fn all_four_bit_comparisons_have_matching_setup_and_proving_rows_and_refuse_false_claims() {
    compare_all::<0>();
    compare_all::<1>();
    compare_all::<2>();
    compare_all::<3>();
    compare_all::<4>();
    compare_all::<5>();
}

#[test]
fn ordered_comparisons_export_the_hand_derived_four_bit_rows() {
    let one = Fr::one();
    for (actual, gap) in [
        (rows(exported::<Compare<4, 0>>()), one),
        (rows(exported::<Compare<4, 1>>()), Fr::from(0u64)),
    ] {
        let expected = golden([
            decomposition(&[(one, 1)], 4, 4),
            decomposition(&[(one, 2)], 8, 4),
            decomposition(&[(power_of_two(4) - gap, 0), (-one, 1), (one, 2)], 12, 5),
            vec![linear(&[(one, 16), (-one, 3)])],
        ]);
        assert_eq!(actual, expected);
    }
}

#[test]
fn division_rows_fix_both_hints_for_all_four_bit_divisions() {
    for x in 0..16u128 {
        for d in 1..16u128 {
            honest(&division::<4, 4, 4>(x, d));
        }
    }
    let fixture = division::<4, 4, 4>(15, 4);
    sound(&fixture, &[3, 4]);
    // Four private inputs followed by 8 operand bits, then quotient and remainder hints.
    for wire in [13, 14] {
        let witness = assignment(&fixture);
        let wrong = *witness.get(wire).expect("division hint") + Fr::one();
        assert!(check_tampered(&fixture, wire, wrong.into()).is_err());
    }
    sound(&division::<128, 128, 124>(u128::MAX, 1), &[3, 4]);
    sound(&division::<128, 124, 128>(u128::MAX, u128::MAX), &[3, 4]);
}

#[test]
fn assertions_range_zero_and_selection_constrain_their_relations() {
    let x = Field::from(5u64);
    let y = Field::from(9u64);
    honest(&Pair::<4, 0> { x, y });
    honest(&Pair::<4, 1> { x, y });
    honest(&Pair::<4, 2> { x, y: x });
    honest(&Pair::<4, 3> { x, y });
    honest(&Pair::<4, 4> { x, y: x });
    honest(&Pair::<4, 5> { x, y });
    honest(&Range::<4> { x, low: x, high: y });
    honest(&AssertZero::<4, false> { x: 0u64.into() });
    honest(&AssertZero::<4, true> { x });
    for condition in [false, true] {
        sound(
            &Selection::<4> {
                x,
                y,
                condition,
                claimed: if condition { x } else { y },
            },
            &[4],
        );
        let fixture = Conditional::<4> {
            x,
            y: if condition { x } else { y },
            condition,
        };
        honest(&fixture);
        if !condition {
            let error = check_tampered(&fixture, 3, 1u64.into()).expect_err("enabled inequality");
            assert_eq!(error.2, Some(RULE));
        }
    }
    sound(
        &Zero::<4> {
            x,
            claimed: 0u64.into(),
        },
        &[2],
    );
    sound(
        &Zero::<4> {
            x: 0u64.into(),
            claimed: 1u64.into(),
        },
        &[2],
    );
    // A range-check witness for a false order is constructed by assigning the low bits
    // of the difference; the recomposition row must reject it even if all digits are boolean.
    let honest_pair = Pair::<4, 0> {
        x: 1u64.into(),
        y: 2u64.into(),
    };
    let mut witness = assignment(&honest_pair);
    *witness.get_mut(1).expect("x") = Fr::from(3u64);
    witness = crate::uint::rows::with_low_bits(witness, 3, 4, Fr::from(3u64));
    witness = crate::uint::rows::with_low_bits(witness, 11, 4, -Fr::from(2u64));
    assert!(exported::<Pair<4, 0>>()
        .first_unsatisfied(&witness)
        .is_some());
}

#[test]
fn wide_comparison_and_division_shapes_have_pinned_counts_and_digests() {
    let actual = [
        (size::<Compare<64, 0>>(), r1cs_digest::<Compare<64, 0>>()),
        (size::<Compare<252, 0>>(), r1cs_digest::<Compare<252, 0>>()),
        (
            size::<Division<64, 64, 64>>(),
            r1cs_digest::<Division<64, 64, 64>>(),
        ),
    ];
    // Values are pinned after the small-circuit row derivation and external relation checks.
    assert_eq!(
        actual.map(|(size, digest)| (size.constraints, size.variables, digest)),
        [
            (
                197,
                197,
                "7a0f923488bb01d2a908d950bff938fde28d49413323bde1bf7e4737867a7222".to_string()
            ),
            (
                761,
                761,
                "c3d5011881589fd9149868a0646d6b0de664d35d1dc11c26e8d1af60336d207c".to_string()
            ),
            (
                328,
                327,
                "99b1adc46f05c31b018de28fd2a43c9bee3cbccc660b79cb32c07fbe43e01c38".to_string()
            ),
        ]
    );
}

#[test]
fn division_refuses_every_dishonest_bounded_quotient_and_remainder_and_a_zero_divisor() {
    use crate::uint::rows::low_bits;
    let r1cs = exported::<Division<4, 4, 4>>();
    // Layout is [1, x, d, claimed_q, claimed_r, x_bits[4], d_bits[4], q, r,
    // q_bits[4], r_bits[4], (d-r-1)_bits[4]]. Claims equal the forged hints,
    // so failures must come from the division's own bounds or product row.
    for (x, d) in [(0u64, 0u64), (15, 0), (0, 1), (15, 1), (15, 4), (15, 15)] {
        for q in 0..16u64 {
            for r in 0..16u64 {
                let (xf, df, qf, rf) = (Fr::from(x), Fr::from(d), Fr::from(q), Fr::from(r));
                let witness = [
                    vec![Fr::one(), xf, df, qf, rf],
                    low_bits(xf, 4),
                    low_bits(df, 4),
                    vec![qf, rf],
                    low_bits(qf, 4),
                    low_bits(rf, 4),
                    low_bits(df - rf - Fr::one(), 4),
                ]
                .concat();
                assert_eq!(
                    r1cs.first_unsatisfied(&witness).is_none(),
                    d != 0 && q * d + r == x && r < d,
                    "x={x}, divisor={d}, q={q}, remainder={r}"
                );
            }
        }
    }
}

#[test]
fn wide_comparisons_cover_both_sides_of_the_252_bit_boundary() {
    use crate::uint::rows::{field, max, power_of_two};
    let values = [Fr::from(0u64), Fr::one(), power_of_two(251), max(252)];
    for x in values {
        for y in values {
            for strict in [false, true] {
                let claim = Fr::from(u64::from(if strict { x < y } else { x <= y }));
                if strict {
                    honest(&Compare::<252, 0> {
                        x: field(x),
                        y: field(y),
                        claimed: field(claim),
                    });
                } else {
                    honest(&Compare::<252, 1> {
                        x: field(x),
                        y: field(y),
                        claimed: field(claim),
                    });
                }
            }
        }
    }
}

fn assert_pair_rows<const OP: u8>() {
    let r1cs = exported::<Pair<4, OP>>();
    for x in 0..16u64 {
        for y in 0..16u64 {
            assert_eq!(
                r1cs.first_unsatisfied(&pair_witness(OP, x, y)).is_none(),
                pair_holds(OP, x, y),
                "op={OP}, x={x}, y={y}"
            );
        }
    }
}

#[test]
fn every_assertion_rejects_coordinated_false_witnesses_after_operand_range_checks() {
    assert_pair_rows::<0>();
    assert_pair_rows::<1>();
    assert_pair_rows::<2>();
    assert_pair_rows::<3>();
    assert_pair_rows::<4>();
    assert_pair_rows::<5>();
}

#[test]
fn zero_assertions_reject_coordinated_false_witnesses() {
    use crate::uint::rows::low_bits;
    use ark_ff::Field as _;
    for x in 0..16u64 {
        let xf = Fr::from(x);
        let zero_witness = [vec![Fr::one(), xf], low_bits(xf, 4)].concat();
        let mut nonzero_witness = zero_witness.clone();
        nonzero_witness.push(xf.inverse().unwrap_or_default());
        assert_eq!(
            exported::<AssertZero<4, false>>()
                .first_unsatisfied(&zero_witness)
                .is_none(),
            x == 0
        );
        assert_eq!(
            exported::<AssertZero<4, true>>()
                .first_unsatisfied(&nonzero_witness)
                .is_none(),
            x != 0
        );
    }
}

#[test]
fn cross_width_equality_observes_high_bits_of_the_wider_operand() {
    for (x, y) in [(0u64, 0u64), (15, 15), (0, 16), (15, 255), (15, u64::MAX)] {
        sound(
            &CrossWidth {
                x: x.into(),
                y: y.into(),
                claimed: u64::from(x == y).into(),
            },
            &[3],
        );
    }
}
