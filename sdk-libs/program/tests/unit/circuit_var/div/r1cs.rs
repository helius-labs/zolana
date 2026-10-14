use ark_bn254::Fr;
use ark_ff::One;
use zolana_program::{circuit::Field, ZkCircuit};

use super::{
    fixtures::{
        inverse_of, ByFour, ByZero, Div, FourOver, DIVISION_BY_ZERO, INVERSE_WIRE, PRODUCT_WIRE,
        QUOTIENT_WIRE, RULE,
    },
    vectors::{Vector, INVALID, VALID, ZERO},
};
use crate::{
    circuit_var::inverse::fixtures::{circuit_refusal, r1cs_synthesis},
    harness::{
        field::{field, HALF_ABOVE, MODULUS_MINUS_1},
        fixture::{
            assignment, breaks_rule, check_constraints, check_tampered, exported, no_free_variable,
            per_vector, with_wires, FreeVariables, ProverRefusal, Visit,
        },
        iden3::{R1cs, R1csHeader},
    },
};

const fn unlabelled(row: usize) -> ProverRefusal {
    ("ProverError.ProofInputsBreakRule", Some(row), None)
}

fn fixture(vector: &Vector) -> Div {
    let (dividend, divisor, quotient) = vector.fields();
    Div {
        dividend,
        divisor,
        quotient,
    }
}

#[test]
fn div_exports_exactly_the_golden_rows_and_header() {
    let one = Fr::one();
    assert_eq!(
        exported::<Div>(),
        R1cs {
            header: R1csHeader::bn254(6, 0, 5, 3),
            a: vec![
                vec![(one, 2)],
                vec![(one, 1)],
                vec![(one, PRODUCT_WIRE), (-one, QUOTIENT_WIRE)],
            ],
            b: vec![
                vec![(one, INVERSE_WIRE)],
                vec![(one, INVERSE_WIRE)],
                vec![(one, 0)],
            ],
            c: vec![vec![(one, 0)], vec![(one, PRODUCT_WIRE)], vec![]],
            wire_labels: vec![0, 1, 2, 3, 4, 5],
        }
    );
}

#[test]
fn a_constant_divisor_is_free_and_a_constant_dividend_scales_the_inverse() {
    let one = Fr::one();
    let quarter = field(HALF_ABOVE) * field(HALF_ABOVE);
    assert_eq!(
        (exported::<ByFour>(), exported::<FourOver>()),
        (
            R1cs {
                header: R1csHeader::bn254(3, 0, 2, 1),
                a: vec![vec![(quarter.into(), 1), (-one, 2)]],
                b: vec![vec![(one, 0)]],
                c: vec![vec![]],
                wire_labels: vec![0, 1, 2],
            },
            R1cs {
                header: R1csHeader::bn254(4, 0, 3, 2),
                a: vec![vec![(one, 1)], vec![(-one, 2), (Fr::from(4u64), 3)]],
                b: vec![vec![(one, 3)], vec![(one, 0)]],
                c: vec![vec![(one, 0)], vec![]],
                wire_labels: vec![0, 1, 2, 3],
            },
        )
    );
}

#[test]
fn a_constant_zero_divisor_is_refused_when_the_circuit_is_built() {
    assert_eq!(
        (
            ByZero::export_r1cs().map(|_| ()).map_err(circuit_refusal),
            ByZero::export_picus_r1cs()
                .map(|_| ())
                .map_err(circuit_refusal),
        ),
        (Err(DIVISION_BY_ZERO), Err(DIVISION_BY_ZERO))
    );
}

#[test]
fn every_valid_vector_checks_three_constraints_although_the_placeholder_divisor_is_zero() {
    assert_eq!(
        per_vector(&VALID, |vector| check_constraints(&fixture(vector))),
        per_vector(&VALID, |_| Ok(3))
    );
}

#[test]
fn the_assignment_is_the_inputs_the_inverse_then_the_product() {
    assert_eq!(
        per_vector(&VALID, |vector| assignment(&fixture(vector))),
        per_vector(&VALID, |vector| {
            let (dividend, divisor, quotient) = vector.fields();
            let inverse = inverse_of(divisor);
            vec![
                Fr::one(),
                dividend.into(),
                divisor.into(),
                quotient.into(),
                inverse.into(),
                quotient.into(),
            ]
        })
    );
}

#[test]
fn every_valid_vector_satisfies_every_row_and_each_tampered_wire_breaks_its_row() {
    let r1cs = exported::<Div>();
    assert_eq!(
        per_vector(&VALID, |vector| {
            let honest = assignment(&fixture(vector));
            let plus_one =
                |wire: usize| with_wires(honest.clone(), &[(wire, honest[wire] + Fr::one())]);
            [
                r1cs.first_unsatisfied(&honest),
                r1cs.first_unsatisfied(&plus_one(QUOTIENT_WIRE)),
                r1cs.first_unsatisfied(&plus_one(INVERSE_WIRE)),
                r1cs.first_unsatisfied(&plus_one(PRODUCT_WIRE)),
                r1cs.first_unsatisfied(&with_wires(honest.clone(), &[(2, Fr::from(0u64))])),
            ]
        }),
        per_vector(&VALID, |_| [None, Some(2), Some(0), Some(1), Some(0)])
    );
}

#[test]
fn a_zero_divisor_breaks_the_inverse_row_whatever_the_witnesses() {
    let r1cs = exported::<Div>();
    let witnesses = ["0", "1", MODULUS_MINUS_1].map(field);
    assert_eq!(
        per_vector(&ZERO, |vector| {
            let (dividend, divisor, quotient) = vector.fields();
            witnesses
                .iter()
                .flat_map(|inverse| witnesses.iter().map(move |product| (inverse, product)))
                .map(|(inverse, product)| {
                    r1cs.first_unsatisfied(&[
                        Fr::one(),
                        dividend.into(),
                        divisor.into(),
                        quotient.into(),
                        (*inverse).into(),
                        (*product).into(),
                    ])
                })
                .collect::<Vec<_>>()
        }),
        per_vector(&ZERO, |_| vec![Some(0); witnesses.len() * witnesses.len()])
    );
}

#[test]
fn every_wrong_quotient_breaks_a_row_whichever_product_witness_it_takes() {
    let r1cs = exported::<Div>();
    assert_eq!(
        per_vector(&INVALID, |vector| {
            let (dividend, divisor, quotient) = vector.fields();
            let inverse = inverse_of(divisor);
            let witness = |product: Field| {
                [
                    Fr::one(),
                    dividend.into(),
                    divisor.into(),
                    quotient.into(),
                    inverse.into(),
                    product.into(),
                ]
            };
            (
                r1cs.first_unsatisfied(&witness(dividend * inverse)),
                r1cs.first_unsatisfied(&witness(quotient)),
            )
        }),
        per_vector(&INVALID, |_| (Some(2), Some(1)))
    );
}

#[test]
fn the_proving_rows_name_the_rule_for_a_wrong_quotient_and_no_rule_for_a_wrong_witness() {
    assert_eq!(
        per_vector(&VALID, |vector| {
            let fixture = fixture(vector);
            let honest = assignment(&fixture);
            let tamper =
                |wire: usize| check_tampered(&fixture, wire, (honest[wire] + Fr::one()).into());
            [
                check_tampered(&fixture, QUOTIENT_WIRE, honest[QUOTIENT_WIRE].into()),
                tamper(QUOTIENT_WIRE),
                tamper(INVERSE_WIRE),
                tamper(PRODUCT_WIRE),
            ]
        }),
        per_vector(&VALID, |_| [
            Ok(()),
            Err(breaks_rule(2, RULE)),
            Err(unlabelled(0)),
            Err(unlabelled(1)),
        ])
    );
}

#[test]
fn a_zero_divisor_is_refused_with_division_by_zero_in_the_r1cs_synthesis_and_by_the_prover() {
    assert_eq!(
        (
            per_vector(&ZERO, |vector| {
                let fixture = fixture(vector);
                (
                    r1cs_synthesis(&fixture),
                    fixture.check_constraints().map_err(circuit_refusal),
                    fixture
                        .export_assignment()
                        .map(|_| ())
                        .map_err(circuit_refusal),
                )
            }),
            per_vector(&VALID, |vector| r1cs_synthesis(&fixture(vector))),
        ),
        (
            per_vector(&ZERO, |_| (
                Err(DIVISION_BY_ZERO),
                Err(DIVISION_BY_ZERO),
                Err(DIVISION_BY_ZERO),
            )),
            per_vector(&VALID, |_| Ok(())),
        )
    );
}

#[test]
fn no_private_variable_is_free_for_any_valid_vector() {
    assert_eq!(
        per_vector(&VALID, |vector| FreeVariables.visit(&fixture(vector))),
        per_vector(&VALID, |_| no_free_variable(3, 5))
    );
}
