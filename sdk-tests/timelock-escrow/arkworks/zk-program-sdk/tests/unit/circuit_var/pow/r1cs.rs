use ark_bn254::Fr;
use ark_ff::One;
use zk_program_sdk::circuit::Field;

use super::{
    fixtures::{witnesses, Pow, Pow5, FIRST_WITNESS_WIRE, POWER_WIRE, RULE},
    vectors::{EXPONENTS, INVALID, VALID},
};
use crate::harness::{
    field::field,
    fixture::{
        assignment, breaks_rule, check_constraints, check_private_variables, check_tampered,
        exported, no_free_variable, per_vector, size, with_wires, ProverRefusal, Size,
    },
    iden3::{R1cs, R1csHeader, Row},
};

const fn unlabelled(row: usize) -> ProverRefusal {
    ("ProverError.ProofInputsBreakRule", Some(row), None)
}

fn rows(r1cs: R1cs) -> (Vec<Row>, Vec<Row>, Vec<Row>) {
    (r1cs.a, r1cs.b, r1cs.c)
}

#[test]
fn x_to_the_5_exports_exactly_the_golden_rows_and_header() {
    let one = Fr::one();
    assert_eq!(
        exported::<Pow5>(),
        R1cs {
            header: R1csHeader::bn254(6, 0, 5, 4),
            a: vec![
                vec![(one, 1)],
                vec![(one, 3)],
                vec![(one, 4)],
                vec![(one, 5), (-one, POWER_WIRE)],
            ],
            b: vec![
                vec![(one, 1)],
                vec![(one, 3)],
                vec![(one, 1)],
                vec![(one, 0)]
            ],
            c: vec![vec![(one, 3)], vec![(one, 4)], vec![(one, 5)], vec![]],
            wire_labels: vec![0, 1, 2, 3, 4, 5],
        }
    );
}

#[test]
fn x_to_the_0_and_to_the_1_allocate_no_witness() {
    let one = Fr::one();
    assert_eq!(
        (
            exported::<Pow<0>>().header,
            rows(exported::<Pow<0>>()),
            exported::<Pow<1>>().header,
            rows(exported::<Pow<1>>()),
        ),
        (
            R1csHeader::bn254(3, 0, 2, 1),
            (
                vec![vec![(one, 0), (-one, POWER_WIRE)]],
                vec![vec![(one, 0)]],
                vec![vec![]]
            ),
            R1csHeader::bn254(3, 0, 2, 1),
            (
                vec![vec![(one, 1), (-one, POWER_WIRE)]],
                vec![vec![(one, 0)]],
                vec![vec![]]
            ),
        )
    );
}

#[test]
fn the_size_is_one_square_per_bit_after_the_first_and_one_product_per_set_bit_after_it() {
    let sizes = [
        size::<Pow<0>>(),
        size::<Pow<1>>(),
        size::<Pow<2>>(),
        size::<Pow<3>>(),
        size::<Pow<5>>(),
        size::<Pow<{ 1 << 32 }>>(),
        size::<Pow<{ 1 << 63 }>>(),
        size::<Pow<{ u64::MAX }>>(),
    ];
    let pinned = [1, 1, 2, 3, 4, 33, 64, 127].map(|constraints| Size {
        constraints,
        variables: constraints + 2,
    });
    assert_eq!(
        (
            sizes,
            EXPONENTS.map(|exponent| Size {
                constraints: witnesses(exponent) + 1,
                variables: witnesses(exponent) + 3,
            })
        ),
        (pinned, pinned)
    );
}

#[test]
fn every_valid_vector_checks_four_constraints() {
    assert_eq!(
        per_vector(&VALID, |vector| {
            let (x, power) = vector.fields();
            check_constraints(&Pow5 { x, power })
        }),
        per_vector(&VALID, |_| Ok(4))
    );
}

#[test]
fn the_assignment_is_x_the_power_then_x_squared_x_to_the_4_and_x_to_the_5() {
    assert_eq!(
        per_vector(&VALID, |vector| {
            let (x, power) = vector.fields();
            assignment(&Pow5 { x, power })
        }),
        per_vector(&VALID, |vector| {
            let (x, power) = vector.fields();
            let squared = x * x;
            [x, power, squared, squared * squared, power]
                .into_iter()
                .fold(vec![Fr::one()], |mut witness, value| {
                    witness.push(value.into());
                    witness
                })
        })
    );
}

#[test]
fn every_valid_vector_satisfies_every_row_and_each_tampered_wire_breaks_its_row() {
    let r1cs = exported::<Pow5>();
    assert_eq!(
        per_vector(&VALID, |vector| {
            let (x, power) = vector.fields();
            let honest = assignment(&Pow5 { x, power });
            let plus_one =
                |wire: usize| with_wires(honest.clone(), &[(wire, honest[wire] + Fr::one())]);
            [
                r1cs.first_unsatisfied(&honest),
                r1cs.first_unsatisfied(&plus_one(POWER_WIRE)),
                r1cs.first_unsatisfied(&plus_one(FIRST_WITNESS_WIRE)),
                r1cs.first_unsatisfied(&plus_one(FIRST_WITNESS_WIRE + 1)),
                r1cs.first_unsatisfied(&plus_one(FIRST_WITNESS_WIRE + 2)),
            ]
        }),
        per_vector(&VALID, |_| [None, Some(3), Some(0), Some(1), Some(2)])
    );
}

#[test]
fn every_invalid_vector_breaks_a_row_with_the_honest_witnesses_or_the_claimed_power() {
    let r1cs = exported::<Pow5>();
    assert_eq!(
        per_vector(&INVALID, |vector| {
            let (x, claimed) = vector.fields();
            let (squared, fourth) = (x * x, x * x * x * x);
            let witness = |fifth: Field| {
                [x, claimed, squared, fourth, fifth].into_iter().fold(
                    vec![Fr::one()],
                    |mut witness, value| {
                        witness.push(value.into());
                        witness
                    },
                )
            };
            (
                r1cs.first_unsatisfied(&witness(fourth * x)),
                r1cs.first_unsatisfied(&witness(claimed)),
            )
        }),
        per_vector(&INVALID, |_| (Some(3), Some(2)))
    );
}

#[test]
fn the_proving_rows_name_the_rule_for_a_wrong_power_and_no_rule_for_a_wrong_witness() {
    assert_eq!(
        per_vector(&VALID, |vector| {
            let (x, power) = vector.fields();
            let fixture = Pow5 { x, power };
            let honest = assignment(&fixture);
            let tamper =
                |wire: usize| check_tampered(&fixture, wire, (honest[wire] + Fr::one()).into());
            [
                check_tampered(&fixture, POWER_WIRE, power),
                tamper(POWER_WIRE),
                tamper(FIRST_WITNESS_WIRE),
                tamper(FIRST_WITNESS_WIRE + 1),
                tamper(FIRST_WITNESS_WIRE + 2),
            ]
        }),
        per_vector(&VALID, |_| [
            Ok(()),
            Err(breaks_rule(3, RULE)),
            Err(unlabelled(0)),
            Err(unlabelled(1)),
            Err(unlabelled(2)),
        ])
    );
}

#[test]
fn no_private_variable_of_x_to_the_5_is_free_and_x_to_the_0_leaves_x_free() {
    let report = check_private_variables(&Pow::<0> {
        x: field("3"),
        power: field("1"),
    });
    assert_eq!(
        (
            per_vector(&VALID, |vector| {
                let (x, power) = vector.fields();
                check_private_variables(&Pow5 { x, power })
            }),
            (
                report.constraints,
                report.private_variables,
                report
                    .free
                    .iter()
                    .map(|free| free.variable)
                    .collect::<Vec<_>>(),
            ),
        ),
        (
            per_vector(&VALID, |_| no_free_variable(4, 5)),
            (1, 2, vec![0]),
        )
    );
}
