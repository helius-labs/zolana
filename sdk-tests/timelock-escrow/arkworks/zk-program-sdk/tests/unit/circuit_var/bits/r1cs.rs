use ark_bn254::Fr;
use ark_ff::{BigInteger, One, PrimeField};
use zk_program_sdk::{circuit::Field, ZkCircuit};

use super::{
    fixtures::{
        low_bits, CheckBits, CheckIsBool, ConstantCheckBits, ConstantIsBool, FromBits, ToBits,
        BIT_WIDTH_TOO_LARGE, BOOL_RULE, FROM_BITS_RULE, NOT_ZERO_OR_ONE, TO_BITS_RULE,
        VALUE_TOO_LARGE, WIDTH_RULE,
    },
    vectors::{Vector, BITS_4, BOOL, WIDTH_1, WIDTH_253, WIDTH_4},
};
use crate::{
    circuit_var::inverse::fixtures::circuit_refusal,
    harness::{
        field::field,
        fixture::{
            assignment, breaks_rule, check_constraints, check_private_variables, check_tampered,
            exported, no_free_variable, per_vector, size, Size,
        },
        iden3::{R1cs, R1csHeader, Row},
    },
};

fn one() -> Fr {
    Fr::one()
}

fn booleanity(wire: usize) -> (Row, Row, Row) {
    (
        vec![(one(), 0), (-one(), wire)],
        vec![(one(), wire)],
        vec![],
    )
}

fn rows_of(rows: Vec<(Row, Row, Row)>) -> (Vec<Row>, Vec<Row>, Vec<Row>) {
    let mut split = (vec![], vec![], vec![]);
    for (a, b, c) in rows {
        split.0.push(a);
        split.1.push(b);
        split.2.push(c);
    }
    split
}

fn weighted(first: usize, count: usize) -> Row {
    (0..count)
        .map(|bit| (Fr::from(1u64 << bit), first + bit))
        .collect()
}

fn low_bit_witness(x: Field, width: usize) -> Vec<Fr> {
    let bits = Fr::from(x).into_bigint().to_bits_le();
    (0..width).map(|bit| Fr::from(bits[bit])).collect()
}

fn fitting(vectors: &[Vector]) -> Vec<Vector> {
    vectors
        .iter()
        .copied()
        .filter(|vector| vector.holds)
        .collect()
}

fn outside(vectors: &[Vector]) -> Vec<Vector> {
    vectors
        .iter()
        .copied()
        .filter(|vector| !vector.holds)
        .collect()
}

#[test]
fn check_bits_4_exports_exactly_four_booleanity_rows_and_one_sum_row() {
    let (mut a, b, c) = rows_of((2..6).map(booleanity).collect());
    let sum: Row = [vec![(-one(), 1)], weighted(2, 4)].concat();
    let (a, b, c) = {
        a.push(sum);
        let (mut b, mut c) = (b, c);
        b.push(vec![(one(), 0)]);
        c.push(vec![]);
        (a, b, c)
    };
    assert_eq!(
        exported::<CheckBits<4>>(),
        R1cs {
            header: R1csHeader::bn254(6, 0, 5, 5),
            a,
            b,
            c,
            wire_labels: (0..6).collect(),
        }
    );
}

#[test]
fn check_is_bool_exports_exactly_x_times_x_minus_1_equals_0() {
    assert_eq!(
        exported::<CheckIsBool>(),
        R1cs {
            header: R1csHeader::bn254(2, 0, 1, 1),
            a: vec![vec![(one(), 1)]],
            b: vec![vec![(-one(), 0), (one(), 1)]],
            c: vec![vec![]],
            wire_labels: vec![0, 1],
        }
    );
}

#[test]
fn from_bits_4_exports_exactly_four_booleanity_rows_and_one_sum_row() {
    let mut a: Vec<Row> = (1..5).map(|wire| vec![(one(), wire)]).collect();
    let mut b: Vec<Row> = (1..5)
        .map(|wire| vec![(-one(), 0), (one(), wire)])
        .collect();
    a.push([weighted(1, 4), vec![(-one(), 5)]].concat());
    b.push(vec![(one(), 0)]);
    assert_eq!(
        exported::<FromBits<4>>(),
        R1cs {
            header: R1csHeader::bn254(6, 0, 5, 5),
            a,
            b,
            c: vec![vec![]; 5],
            wire_labels: (0..6).collect(),
        }
    );
}

#[test]
fn to_bits_4_decomposes_then_asserts_each_claimed_bit() {
    let (mut a, mut b, mut c) = rows_of((6..10).map(booleanity).collect());
    a.push([vec![(-one(), 1)], weighted(6, 4)].concat());
    b.push(vec![(one(), 0)]);
    c.push(vec![]);
    for bit in 0..4 {
        a.push(vec![(-one(), 2 + bit), (one(), 6 + bit)]);
        b.push(vec![(one(), 0)]);
        c.push(vec![]);
    }
    assert_eq!(
        exported::<ToBits<4>>(),
        R1cs {
            header: R1csHeader::bn254(10, 0, 9, 9),
            a,
            b,
            c,
            wire_labels: (0..10).collect(),
        }
    );
}

#[test]
fn the_sizes_grow_by_one_constraint_and_one_witness_per_bit() {
    let bits = |width: usize| Size {
        constraints: width + 1,
        variables: width + 2,
    };
    assert_eq!(
        (
            [
                size::<CheckBits<1>>(),
                size::<CheckBits<4>>(),
                size::<CheckBits<64>>(),
                size::<CheckBits<253>>(),
            ],
            [
                size::<FromBits<1>>(),
                size::<FromBits<4>>(),
                size::<FromBits<64>>()
            ],
            [
                size::<ToBits<1>>(),
                size::<ToBits<4>>(),
                size::<ToBits<64>>()
            ],
        ),
        (
            [bits(1), bits(4), bits(64), bits(253)],
            [bits(1), bits(4), bits(64)],
            [1, 4, 64].map(|width| Size {
                constraints: 2 * width + 1,
                variables: 2 * width + 2,
            }),
        )
    );
}

#[test]
fn a_constant_that_passes_its_check_adds_nothing() {
    let empty = R1cs {
        header: R1csHeader::bn254(2, 0, 1, 0),
        a: vec![],
        b: vec![],
        c: vec![],
        wire_labels: vec![0, 1],
    };
    assert_eq!(
        (
            exported::<ConstantCheckBits<7, 3>>(),
            exported::<ConstantIsBool<1>>(),
        ),
        (
            empty,
            R1cs {
                header: R1csHeader::bn254(2, 0, 1, 0),
                a: vec![],
                b: vec![],
                c: vec![],
                wire_labels: vec![0, 1],
            }
        )
    );
}

#[test]
fn a_width_of_254_and_a_failing_constant_are_refused_when_the_circuit_is_built() {
    let refused = |result: Result<Vec<u8>, _>| result.map(|_| ()).map_err(circuit_refusal);
    assert_eq!(
        [
            refused(CheckBits::<254>::export_r1cs()),
            refused(ToBits::<254>::export_r1cs()),
            refused(ConstantCheckBits::<8, 3>::export_r1cs()),
            refused(ConstantIsBool::<2>::export_r1cs()),
        ],
        [
            Err(BIT_WIDTH_TOO_LARGE),
            Err(BIT_WIDTH_TOO_LARGE),
            Err(VALUE_TOO_LARGE),
            Err(NOT_ZERO_OR_ONE),
        ]
    );
}

#[test]
fn every_fitting_value_checks_one_constraint_per_bit_plus_the_sum() {
    assert_eq!(
        (
            per_vector(&fitting(&WIDTH_1), |vector| check_constraints(
                &CheckBits::<1> { x: vector.field() }
            )),
            per_vector(&fitting(&WIDTH_4), |vector| check_constraints(
                &CheckBits::<4> { x: vector.field() }
            )),
            per_vector(&fitting(&WIDTH_253), |vector| check_constraints(
                &CheckBits::<253> { x: vector.field() }
            )),
            per_vector(&fitting(&BOOL), |vector| check_constraints(&CheckIsBool {
                x: vector.field()
            })),
        ),
        (
            per_vector(&fitting(&WIDTH_1), |_| Ok(2)),
            per_vector(&fitting(&WIDTH_4), |_| Ok(5)),
            per_vector(&fitting(&WIDTH_253), |_| Ok(254)),
            per_vector(&fitting(&BOOL), |_| Ok(1)),
        )
    );
}

#[test]
fn every_honest_bit_claim_checks_and_is_assigned_after_x() {
    let honest: Vec<_> = BITS_4.into_iter().filter(|vector| vector.holds).collect();
    assert_eq!(
        per_vector(&honest, |vector| {
            let (x, bits) = (vector.value(), vector.bits());
            (
                check_constraints(&ToBits::<4> { x, bits }),
                check_constraints(&FromBits::<4> { bits, value: x }),
                assignment(&CheckBits::<4> { x }),
            )
        }),
        per_vector(&honest, |vector| {
            let bits = vector.bits().map(Fr::from);
            (
                Ok(9),
                Ok(5),
                [vec![one(), vector.value().into()], bits.to_vec()].concat(),
            )
        })
    );
}

#[test]
fn a_value_outside_the_width_breaks_the_sum_row_whatever_boolean_bits_it_takes() {
    let every_4_bits: Vec<Vec<Fr>> = (0..16u64)
        .map(|bits| low_bits::<4>(bits).map(Fr::from).to_vec())
        .collect();
    let with = |x: Field, bits: &[Fr]| [vec![one(), x.into()], bits.to_vec()].concat();
    let r1cs_4 = exported::<CheckBits<4>>();
    let r1cs_253 = exported::<CheckBits<253>>();
    let r1cs_1 = exported::<CheckBits<1>>();
    assert_eq!(
        (
            per_vector(&outside(&WIDTH_4), |vector| every_4_bits
                .iter()
                .map(|bits| r1cs_4.first_unsatisfied(&with(vector.field(), bits)))
                .collect::<Vec<_>>()),
            per_vector(&outside(&WIDTH_253), |vector| [
                vec![Fr::from(0u64); 253],
                vec![one(); 253],
                low_bit_witness(vector.field(), 253),
            ]
            .map(|bits| r1cs_253.first_unsatisfied(&with(vector.field(), &bits)))),
            per_vector(&outside(&WIDTH_1), |vector| [0u64, 1].map(
                |bit| r1cs_1.first_unsatisfied(&with(vector.field(), &[Fr::from(bit)]))
            )),
        ),
        (
            per_vector(&outside(&WIDTH_4), |_| vec![Some(4); 16]),
            per_vector(&outside(&WIDTH_253), |_| [Some(253); 3]),
            per_vector(&outside(&WIDTH_1), |_| [Some(1); 2]),
        )
    );
}

#[test]
fn a_non_boolean_decomposition_that_sums_to_x_breaks_a_booleanity_row() {
    let five = |bits: [u64; 4]| [vec![one(), Fr::from(5u64)], bits.map(Fr::from).to_vec()].concat();
    let r1cs = exported::<CheckBits<4>>();
    let from_bits = exported::<FromBits<4>>();
    let minus_one = -one();
    assert_eq!(
        (
            r1cs.first_unsatisfied(&five([1, 0, 1, 0])),
            r1cs.first_unsatisfied(&five([3, 1, 0, 0])),
            r1cs.first_unsatisfied(&five([1, 2, 0, 0])),
            r1cs.first_unsatisfied(&[
                one(),
                Fr::from(5u64),
                Fr::from(7u64),
                minus_one,
                Fr::from(0u64),
                Fr::from(0u64)
            ]),
            from_bits.first_unsatisfied(&[
                one(),
                Fr::from(3u64),
                one(),
                Fr::from(0u64),
                Fr::from(0u64),
                Fr::from(5u64)
            ]),
        ),
        (None, Some(0), Some(1), Some(0), Some(0))
    );
}

#[test]
fn the_proving_rows_name_the_width_and_bool_rules() {
    let check_bits = CheckBits::<4> { x: field("5") };
    let from_bits = FromBits::<4> {
        bits: low_bits(5),
        value: field("5"),
    };
    let to_bits = ToBits::<4> {
        x: field("5"),
        bits: low_bits(5),
    };
    let is_bool = CheckIsBool { x: field("1") };
    assert_eq!(
        [
            check_tampered(&check_bits, 1, field("16")),
            check_tampered(&check_bits, 2, field("2")),
            check_tampered(&check_bits, 3, field("1")),
            check_tampered(&is_bool, 1, field("2")),
            check_tampered(&from_bits, 1, field("2")),
            check_tampered(&from_bits, 5, field("6")),
            check_tampered(&to_bits, 2, field("0")),
            check_tampered(&to_bits, 1, field("4")),
        ],
        [
            Err(breaks_rule(4, WIDTH_RULE)),
            Err(breaks_rule(0, WIDTH_RULE)),
            Err(breaks_rule(4, WIDTH_RULE)),
            Err(breaks_rule(0, BOOL_RULE)),
            Err(breaks_rule(0, BOOL_RULE)),
            Err(breaks_rule(4, FROM_BITS_RULE)),
            Err(breaks_rule(5, TO_BITS_RULE)),
            Err(breaks_rule(4, WIDTH_RULE)),
        ]
    );
}

#[test]
fn no_private_variable_is_free_in_any_bits_fixture() {
    let honest: Vec<_> = BITS_4.into_iter().filter(|vector| vector.holds).collect();
    assert_eq!(
        (
            per_vector(&fitting(&WIDTH_4), |vector| check_private_variables(
                &CheckBits::<4> { x: vector.field() }
            )),
            per_vector(&fitting(&BOOL), |vector| check_private_variables(
                &CheckIsBool { x: vector.field() }
            )),
            per_vector(&honest, |vector| (
                check_private_variables(&FromBits::<4> {
                    bits: vector.bits(),
                    value: vector.value()
                }),
                check_private_variables(&ToBits::<4> {
                    x: vector.value(),
                    bits: vector.bits()
                }),
            )),
        ),
        (
            per_vector(&fitting(&WIDTH_4), |_| no_free_variable(5, 5)),
            per_vector(&fitting(&BOOL), |_| no_free_variable(1, 1)),
            per_vector(&honest, |_| (
                no_free_variable(5, 5),
                no_free_variable(9, 9)
            )),
        )
    );
}
