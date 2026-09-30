use ark_bn254::Fr;
use ark_ff::One;
use zolana_program::circuit::Field;

use super::{
    fixtures::{
        Borrowed, Constants, FromBool, IntoVar, Owned, FIRST_BIT, RULE, WIDTH_RULE, X_WIRE,
    },
    vectors::{invalid, valid, Vector, WIDTHS},
};
use crate::{
    harness::{
        digest::r1cs_digest,
        fixture::{
            assignment, breaks_rule, check_constraints, check_private_variables, check_tampered,
            export, exported, first_unsatisfied, no_free_variable, size, ProverRefusal, Size,
        },
        iden3::{read_r1cs, R1cs, R1csHeader},
    },
    uint::{
        at_widths,
        picus_form::circom_form,
        rows::{
            bit_pattern, decomposition, field, golden, int, linear, low_bits, power_of_two,
            product, rows,
        },
        Widths,
    },
};

fn honest(x: Fr, bits: u32) -> Vec<Fr> {
    [vec![Fr::one(), x], low_bits(x, bits as usize)].concat()
}

#[test]
fn a_4_bit_try_from_exports_exactly_the_golden_rows_and_header() {
    let (a, b, c) = golden([decomposition(&[(Fr::one(), X_WIRE)], FIRST_BIT, 4)]);
    assert_eq!(
        exported::<Borrowed<4>>(),
        R1cs {
            header: R1csHeader::bn254(6, 0, 5, 5),
            a,
            b,
            c,
            wire_labels: vec![0, 1, 2, 3, 4, 5],
        }
    );
}

struct Forms;

impl Widths for Forms {
    type Output = bool;

    fn at<const BITS: u32>(&self) -> bool {
        export::<Borrowed<BITS>>() == export::<Owned<BITS>>()
    }
}

#[test]
fn the_owned_and_borrowed_forms_export_byte_identical_r1cs_at_every_width() {
    assert_eq!(
        at_widths!(&Forms, [1, 4, 64, 252, 253]),
        WIDTHS.map(|bits| (bits, true)).to_vec()
    );
}

struct Sizes;

impl Widths for Sizes {
    type Output = Size;

    fn at<const BITS: u32>(&self) -> Size {
        size::<Borrowed<BITS>>()
    }
}

#[test]
fn a_range_check_over_bits_costs_bits_plus_one_constraints_and_bits_variables() {
    assert_eq!(
        at_widths!(&Sizes, [1, 4, 64, 252, 253]),
        WIDTHS
            .map(|bits| {
                let bits_usize = bits as usize;
                (
                    bits,
                    Size {
                        constraints: bits_usize + 1,
                        variables: bits_usize + 2,
                    },
                )
            })
            .to_vec()
    );
}

#[test]
fn the_64_and_252_bit_range_checks_export_the_derived_rows_and_pinned_digests() {
    let derived = |bits| golden([decomposition(&[(Fr::one(), X_WIRE)], FIRST_BIT, bits)]);
    assert_eq!(
        (
            rows(exported::<Borrowed<64>>()),
            rows(exported::<Borrowed<252>>()),
            r1cs_digest::<Borrowed<64>>(),
            r1cs_digest::<Borrowed<252>>(),
        ),
        (
            derived(64),
            derived(252),
            "ad2525ca1b9164e048533f17ba28c73f00ebcd2f9b1250ba54e7649bc5b5e926".to_string(),
            "3b364a68f1d1b132860d5c9390b53446b10368f459bf166fcd39cd01d2a54cc1".to_string(),
        )
    );
}

struct Complete;

impl Widths for Complete {
    type Output = Vec<(
        &'static str,
        (Result<usize, ProverRefusal>, Vec<Fr>, Option<usize>),
    )>;

    fn at<const BITS: u32>(&self) -> Self::Output {
        valid(BITS)
            .into_iter()
            .map(|Vector { name, x }| {
                let fixture = Borrowed::<BITS> { x: field(x) };
                let witness = assignment(&fixture);
                let unsatisfied = first_unsatisfied::<Borrowed<BITS>>(&witness);
                (name, (check_constraints(&fixture), witness, unsatisfied))
            })
            .collect()
    }
}

#[test]
fn every_value_below_two_to_the_width_satisfies_every_row_with_its_binary_digits() {
    assert_eq!(
        at_widths!(&Complete, [1, 4, 64, 252, 253]),
        WIDTHS
            .map(|bits| {
                let checked = valid(bits)
                    .into_iter()
                    .map(|Vector { name, x }| {
                        (name, (Ok(bits as usize + 1), honest(x, bits), None))
                    })
                    .collect();
                (bits, checked)
            })
            .to_vec()
    );
}

#[test]
fn at_4_bits_only_the_binary_digits_of_a_value_below_16_satisfy_the_rows() {
    let r1cs = exported::<Borrowed<4>>();
    let satisfying: Vec<(u64, u64)> = (0..32u64)
        .flat_map(|x| (0..16u64).map(move |pattern| (x, pattern)))
        .filter(|(x, pattern)| {
            let witness = [vec![Fr::one(), Fr::from(*x)], bit_pattern(*pattern, 4)].concat();
            r1cs.first_unsatisfied(&witness).is_none()
        })
        .collect();
    assert_eq!(satisfying, (0..16u64).map(|x| (x, x)).collect::<Vec<_>>());
}

#[test]
fn the_circom_form_of_the_export_accepts_exactly_the_witnesses_the_export_accepts() {
    let (sdk, circom_form) = (
        exported::<Borrowed<4>>(),
        read_r1cs(&circom_form(&export::<Borrowed<4>>())),
    );
    let accepted = |r1cs: &R1cs| -> Vec<(u64, u64)> {
        (0..32u64)
            .flat_map(|x| (0..16u64).map(move |pattern| (x, pattern)))
            .filter(|(x, pattern)| {
                let witness = [vec![Fr::one(), Fr::from(*x)], bit_pattern(*pattern, 4)].concat();
                r1cs.first_unsatisfied(&witness).is_none()
            })
            .collect()
    };
    assert_eq!(
        (accepted(&circom_form), circom_form.header),
        (accepted(&sdk), sdk.header)
    );
}

struct Overflowing;

impl Widths for Overflowing {
    type Output = Vec<(&'static str, Option<usize>)>;

    fn at<const BITS: u32>(&self) -> Self::Output {
        invalid(BITS)
            .into_iter()
            .map(|Vector { name, x }| (name, first_unsatisfied::<Borrowed<BITS>>(&honest(x, BITS))))
            .collect()
    }
}

#[test]
fn a_value_that_does_not_fit_leaves_exactly_the_sum_row_unsatisfied_at_every_width() {
    assert_eq!(
        at_widths!(&Overflowing, [1, 4, 64, 252, 253]),
        WIDTHS
            .map(|bits| {
                let broken = invalid(bits)
                    .into_iter()
                    .map(|vector| (vector.name, Some(bits as usize)))
                    .collect();
                (bits, broken)
            })
            .to_vec()
    );
}

struct Tampered;

impl Widths for Tampered {
    type Output = [Result<(), ProverRefusal>; 3];

    fn at<const BITS: u32>(&self) -> Self::Output {
        let fixture = Borrowed::<BITS> {
            x: field(power_of_two(BITS) - Fr::one()),
        };
        let tamper = |wire, value: Fr| check_tampered(&fixture, wire, Field::from(value));
        [
            tamper(X_WIRE, power_of_two(BITS) - Fr::one()),
            tamper(X_WIRE, power_of_two(BITS)),
            tamper(FIRST_BIT, int(2)),
        ]
    }
}

#[test]
fn the_proving_rows_name_the_width_rule_for_a_tampered_value_or_digit() {
    assert_eq!(
        at_widths!(&Tampered, [1, 4, 64, 252, 253]),
        WIDTHS
            .map(|bits| {
                (
                    bits,
                    [
                        Ok(()),
                        Err(breaks_rule(bits as usize, WIDTH_RULE)),
                        Err(breaks_rule(0, WIDTH_RULE)),
                    ],
                )
            })
            .to_vec()
    );
}

struct Free;

impl Widths for Free {
    type Output = Vec<(&'static str, zolana_program::testing::PrivateVariableReport)>;

    fn at<const BITS: u32>(&self) -> Self::Output {
        valid(BITS)
            .into_iter()
            .map(|Vector { name, x }| {
                (
                    name,
                    check_private_variables(&Borrowed::<BITS> { x: field(x) }),
                )
            })
            .collect()
    }
}

#[test]
fn no_private_variable_is_free_at_every_width() {
    assert_eq!(
        at_widths!(&Free, [1, 4, 64, 252, 253]),
        WIDTHS
            .map(|bits| {
                let report = || no_free_variable(bits as usize + 1, bits as usize + 1);
                let reports = valid(bits)
                    .into_iter()
                    .map(|vector| (vector.name, report()))
                    .collect();
                (bits, reports)
            })
            .to_vec()
    );
}

#[test]
fn into_circuit_var_adds_only_the_row_asserting_it() {
    let one = Fr::one();
    assert_eq!(
        rows(exported::<IntoVar<4>>()),
        golden([
            decomposition(&[(one, 1)], 3, 4),
            vec![linear(&[(one, 1), (-one, 2)])],
        ])
    );
}

#[test]
fn from_bool_adds_no_row_beyond_the_bool_input_check() {
    let one = Fr::one();
    let fixture = |bit: bool| FromBool::<4> {
        bit,
        claimed: Field::from(u64::from(bit)),
    };
    assert_eq!(
        (
            rows(exported::<FromBool<4>>()),
            rows(exported::<FromBool<253>>()),
            check_constraints(&fixture(false)),
            check_constraints(&fixture(true)),
        ),
        (
            golden([vec![
                product(&[(one, 1)], &[(-one, 0), (one, 1)], &[]),
                linear(&[(one, 1), (-one, 2)]),
            ]]),
            golden([vec![
                product(&[(one, 1)], &[(-one, 0), (one, 1)], &[]),
                linear(&[(one, 1), (-one, 2)]),
            ]]),
            Ok(2),
            Ok(2),
        )
    );
}

#[test]
fn a_constant_uint_adds_no_range_check_row() {
    let one = Fr::one();
    let claim = linear(&[(int(15), 0), (-one, 1)]);
    assert_eq!(
        (
            exported::<Constants>(),
            check_constraints(&Constants {
                x: Field::from(15u64)
            })
        ),
        (
            R1cs {
                header: R1csHeader::bn254(2, 0, 1, 2),
                a: vec![claim.0.clone(), claim.0],
                b: vec![claim.1.clone(), claim.1],
                c: vec![vec![], vec![]],
                wire_labels: vec![0, 1],
            },
            Ok(2)
        )
    );
}

#[test]
fn a_rule_other_than_the_width_rule_labels_the_claim_row() {
    let fixture = IntoVar::<4> {
        x: Field::from(9u64),
        claimed: Field::from(9u64),
    };
    assert_eq!(
        (
            check_tampered(&fixture, 2, Field::from(9u64)),
            check_tampered(&fixture, 2, Field::from(10u64)),
        ),
        (Ok(()), Err(breaks_rule(5, RULE)))
    );
}

#[test]
fn bool_conversion_and_constants_refuse_every_wrong_four_bit_claim() {
    for bit in [false, true] {
        let fixture = FromBool::<4> {
            bit,
            claimed: Field::from(u64::from(bit)),
        };
        for claim in 0..16u64 {
            assert_eq!(
                check_tampered(&fixture, 2, claim.into()).is_ok(),
                claim == u64::from(bit)
            );
        }
    }
    let fixture = Constants { x: 15u64.into() };
    for claim in 0..16u64 {
        assert_eq!(
            check_tampered(&fixture, 1, claim.into()).is_ok(),
            claim == 15
        );
    }
}
