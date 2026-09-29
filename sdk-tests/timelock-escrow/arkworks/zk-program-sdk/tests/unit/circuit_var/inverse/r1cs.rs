use ark_bn254::Fr;
use ark_ff::One;
use zk_program_sdk::{
    circuit::{Field, LabelKind, VariableRole},
    testing, ZkCircuit,
};

use super::{
    fixtures::{
        circuit_refusal, honest, r1cs_synthesis, Inverse, InverseOfFour, InverseOfZero, Unasserted,
        CLAIMED_WIRE, DIVISION_BY_ZERO, FILE, INVERSE_WIRE, RULE,
    },
    vectors::{INVALID, VALID, ZERO},
};
use crate::harness::{
    field::{field, HALF_ABOVE, MODULUS_MINUS_1},
    fixture::{
        assignment, breaks_rule, check_constraints, check_tampered, exported, no_free_variable,
        per_vector, with_wires, FreeVariables, ProverRefusal, Visit,
    },
    iden3::{R1cs, R1csHeader},
};

const UNLABELLED_ROW_0: ProverRefusal = ("ProverError.ProofInputsBreakRule", Some(0), None);

#[test]
fn inverse_exports_exactly_the_golden_rows_and_header() {
    let one = Fr::one();
    assert_eq!(
        exported::<Inverse>(),
        R1cs {
            header: R1csHeader::bn254(4, 0, 3, 2),
            a: vec![
                vec![(one, 1)],
                vec![(one, INVERSE_WIRE), (-one, CLAIMED_WIRE)]
            ],
            b: vec![vec![(one, INVERSE_WIRE)], vec![(one, 0)]],
            c: vec![vec![(one, 0)], vec![]],
            wire_labels: vec![0, 1, 2, 3],
        }
    );
}

#[test]
fn inverting_a_variable_adds_exactly_one_constraint_and_one_witness() {
    let one = Fr::one();
    let fixture = Unasserted { x: field("2") };
    assert_eq!(
        (
            exported::<Unasserted>(),
            assignment(&fixture),
            check_constraints(&fixture)
        ),
        (
            R1cs {
                header: R1csHeader::bn254(3, 0, 2, 1),
                a: vec![vec![(one, 1)]],
                b: vec![vec![(one, 2)]],
                c: vec![vec![(one, 0)]],
                wire_labels: vec![0, 1, 2],
            },
            vec![one, Fr::from(2u64), field(HALF_ABOVE).into()],
            Ok(1)
        )
    );
}

#[test]
fn inverting_a_constant_puts_the_inverse_on_variable_zero_and_allocates_nothing() {
    let one = Fr::one();
    let quarter = field(HALF_ABOVE) * field(HALF_ABOVE);
    assert_eq!(
        (
            exported::<InverseOfFour>(),
            check_constraints(&InverseOfFour { inverse: quarter }),
        ),
        (
            R1cs {
                header: R1csHeader::bn254(2, 0, 1, 1),
                a: vec![vec![(quarter.into(), 0), (-one, 1)]],
                b: vec![vec![(one, 0)]],
                c: vec![vec![]],
                wire_labels: vec![0, 1],
            },
            Ok(1)
        )
    );
}

#[test]
fn every_valid_vector_checks_two_constraints_although_the_placeholder_x_is_zero() {
    assert_eq!(
        per_vector(&VALID, |vector| {
            let (x, inverse) = vector.fields();
            check_constraints(&Inverse { x, inverse })
        }),
        per_vector(&VALID, |_| Ok(2))
    );
}

#[test]
fn the_assignment_is_x_the_claim_then_the_inverse_witness() {
    assert_eq!(
        per_vector(&VALID, |vector| {
            let (x, inverse) = vector.fields();
            assignment(&Inverse { x, inverse })
        }),
        per_vector(&VALID, |vector| {
            let (x, inverse) = vector.fields();
            vec![Fr::one(), x.into(), inverse.into(), inverse.into()]
        })
    );
}

#[test]
fn every_valid_vector_satisfies_every_row_and_each_tampered_wire_breaks_its_row() {
    let r1cs = exported::<Inverse>();
    assert_eq!(
        per_vector(&VALID, |vector| {
            let (x, inverse) = vector.fields();
            let honest = assignment(&Inverse { x, inverse });
            let plus_one =
                |wire: usize| with_wires(honest.clone(), &[(wire, honest[wire] + Fr::one())]);
            [
                r1cs.first_unsatisfied(&honest),
                r1cs.first_unsatisfied(&plus_one(CLAIMED_WIRE)),
                r1cs.first_unsatisfied(&plus_one(INVERSE_WIRE)),
                r1cs.first_unsatisfied(&with_wires(honest.clone(), &[(1, Fr::from(0u64))])),
            ]
        }),
        per_vector(&VALID, |_| [None, Some(1), Some(0), Some(0)])
    );
}

#[test]
fn a_zero_x_breaks_the_inverse_row_whatever_the_witness() {
    let r1cs = exported::<Inverse>();
    let witnesses = ["0", "1", "2", MODULUS_MINUS_1].map(field);
    assert_eq!(
        per_vector(&ZERO, |vector| {
            let (x, inverse) = vector.fields();
            witnesses
                .iter()
                .map(|witness| {
                    r1cs.first_unsatisfied(&[
                        Fr::one(),
                        x.into(),
                        inverse.into(),
                        (*witness).into(),
                    ])
                })
                .collect::<Vec<_>>()
        }),
        per_vector(&ZERO, |_| vec![Some(0); witnesses.len()])
    );
}

#[test]
fn every_wrong_inverse_breaks_a_row_whichever_witness_it_takes() {
    let r1cs = exported::<Inverse>();
    assert_eq!(
        per_vector(&INVALID, |vector| {
            let (x, claimed) = vector.fields();
            let witness = |inverse: Field| [Fr::one(), x.into(), claimed.into(), inverse.into()];
            (
                r1cs.first_unsatisfied(&witness(honest(x).inverse)),
                r1cs.first_unsatisfied(&witness(claimed)),
            )
        }),
        per_vector(&INVALID, |_| (Some(1), Some(0)))
    );
}

#[test]
fn the_proving_rows_name_the_rule_for_a_wrong_claim_and_no_rule_for_a_wrong_witness() {
    assert_eq!(
        per_vector(&VALID, |vector| {
            let (x, inverse) = vector.fields();
            let fixture = Inverse { x, inverse };
            let honest = assignment(&fixture);
            let tamper = |wire: usize, value: Fr| check_tampered(&fixture, wire, value.into());
            [
                tamper(CLAIMED_WIRE, honest[CLAIMED_WIRE]),
                tamper(CLAIMED_WIRE, honest[CLAIMED_WIRE] + Fr::one()),
                tamper(INVERSE_WIRE, honest[INVERSE_WIRE] + Fr::one()),
                tamper(1, Fr::from(0u64)),
            ]
        }),
        per_vector(&VALID, |_| [
            Ok(()),
            Err(breaks_rule(1, RULE)),
            Err(UNLABELLED_ROW_0),
            Err(UNLABELLED_ROW_0),
        ])
    );
}

#[test]
fn a_zero_x_is_refused_with_division_by_zero_in_the_r1cs_synthesis_and_by_the_prover() {
    assert_eq!(
        (
            per_vector(&ZERO, |vector| {
                let (x, inverse) = vector.fields();
                let fixture = Inverse { x, inverse };
                (
                    r1cs_synthesis(&fixture),
                    fixture.check_constraints().map_err(circuit_refusal),
                    fixture
                        .export_assignment()
                        .map(|_| ())
                        .map_err(circuit_refusal),
                )
            }),
            per_vector(&VALID, |vector| {
                let (x, inverse) = vector.fields();
                r1cs_synthesis(&Inverse { x, inverse })
            }),
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
fn a_constant_zero_divisor_is_refused_when_the_circuit_is_built() {
    assert_eq!(
        (
            InverseOfZero::export_r1cs()
                .map(|_| ())
                .map_err(circuit_refusal),
            InverseOfZero::export_picus_r1cs()
                .map(|_| ())
                .map_err(circuit_refusal),
        ),
        (Err(DIVISION_BY_ZERO), Err(DIVISION_BY_ZERO))
    );
}

#[test]
fn the_inverse_witness_and_its_row_carry_no_label() {
    let labels = testing::constraint_labels(&honest(field("2"))).expect("labels");
    let input = LabelKind::Allocation(VariableRole::Constrained);
    assert_eq!(
        labels
            .iter()
            .map(|label| (
                label.kind,
                label.text,
                label.file == FILE,
                label.rows.clone(),
                label.private_variables.clone()
            ))
            .collect::<Vec<_>>(),
        vec![
            (input, "a field proof input", false, 0..0, 0..1),
            (input, "a field proof input", false, 0..0, 1..2),
            (LabelKind::Check, RULE, true, 1..2, 3..3),
        ]
    );
}

#[test]
fn no_private_variable_is_free_for_any_valid_vector() {
    assert_eq!(
        per_vector(&VALID, |vector| {
            let (x, inverse) = vector.fields();
            FreeVariables.visit(&Inverse { x, inverse })
        }),
        per_vector(&VALID, |_| no_free_variable(2, 3))
    );
}
