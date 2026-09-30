use ark_bn254::Fr;
use ark_ff::One;
use zolana_program::{circuit::CircuitVar, circuit::Field, ZkCircuit};

use super::{
    fixtures::{every_form, form_names, DoubleNegation, Negated, PlusNegation, Unasserted, RULE},
    vectors::{INVALID, VALID},
};
use crate::harness::{
    field::field,
    fixture::{
        assignment, breaks_rule, check_constraints, check_tampered, each, expected, exported,
        no_free_variable, per_vector, with_wires, Assignment, CheckConstraints, Export, Fixture,
        FreeVariables, ProverRefusal, Visit,
    },
    iden3::{R1cs, R1csHeader, Row},
};

const NEGATION_WIRE: usize = 2;

fn rows(r1cs: R1cs) -> (Vec<Row>, Vec<Row>, Vec<Row>) {
    (r1cs.a, r1cs.b, r1cs.c)
}

fn tampered_negation(witness: Vec<Fr>) -> Vec<Fr> {
    let negation = witness[NEGATION_WIRE] + Fr::one();
    with_wires(witness, &[(NEGATION_WIRE, negation)])
}

#[test]
fn minus_a_exports_exactly_the_golden_row_and_header() {
    let one = Fr::one();
    assert_eq!(
        exported::<Negated<1>>(),
        R1cs {
            header: R1csHeader::bn254(3, 0, 2, 1),
            a: vec![vec![(-one, 1), (-one, 2)]],
            b: vec![vec![(one, 0)]],
            c: vec![vec![]],
            wire_labels: vec![0, 1, 2],
        }
    );
}

#[test]
fn both_forms_export_byte_identical_r1cs() {
    assert_eq!(
        every_form(&Export, VALID[0].fields()),
        each(
            &form_names(),
            Negated::<1>::export_r1cs().expect("r1cs export")
        )
    );
}

#[test]
fn negating_allocates_no_variable_and_adds_no_constraint() {
    let fixture = Unasserted { value: field("3") };
    assert_eq!(
        (
            exported::<Unasserted>(),
            assignment(&fixture),
            check_constraints(&fixture)
        ),
        (
            R1cs {
                header: R1csHeader::bn254(2, 0, 1, 0),
                a: vec![],
                b: vec![],
                c: vec![],
                wire_labels: vec![0, 1],
            },
            vec![Fr::one(), Fr::from(3u64)],
            Ok(0)
        )
    );
}

#[test]
fn a_double_negation_inlines_to_exactly_the_value() {
    let one = Fr::one();
    assert_eq!(
        rows(exported::<DoubleNegation>()),
        (
            vec![vec![(one, 1), (-one, 2)]],
            vec![vec![(one, 0)]],
            vec![vec![]]
        )
    );
}

#[test]
fn a_plus_minus_a_cancels_to_no_entry_for_a() {
    let one = Fr::one();
    assert_eq!(
        rows(exported::<PlusNegation>()),
        (vec![vec![(-one, 2)]], vec![vec![(one, 0)]], vec![vec![]])
    );
}

#[test]
fn every_valid_vector_checks_one_constraint_in_every_form() {
    assert_eq!(
        per_vector(&VALID, |vector| every_form(
            &CheckConstraints,
            vector.fields()
        )),
        expected(&VALID, &form_names(), |_, _| Ok(1))
    );
}

#[test]
fn the_assignment_is_the_constant_one_then_the_inputs() {
    assert_eq!(
        per_vector(&VALID, |vector| every_form(&Assignment, vector.fields())),
        expected(&VALID, &form_names(), |vector, _| {
            let (value, negation) = vector.fields();
            vec![Fr::one(), value.into(), negation.into()]
        })
    );
}

struct ExportedRow;

impl Visit<CircuitVar> for ExportedRow {
    type Output = (Option<usize>, Option<usize>);

    fn visit<F: Fixture<CircuitVar>>(&self, fixture: &F) -> Self::Output {
        let r1cs = exported::<F>();
        let honest = assignment(fixture);
        (
            r1cs.first_unsatisfied(&honest),
            r1cs.first_unsatisfied(&tampered_negation(honest.clone())),
        )
    }
}

#[test]
fn every_valid_vector_satisfies_the_row_and_a_tampered_negation_breaks_it() {
    assert_eq!(
        per_vector(&VALID, |vector| every_form(&ExportedRow, vector.fields())),
        expected(&VALID, &form_names(), |_, _| (None, Some(0)))
    );
}

#[test]
fn every_invalid_vector_breaks_the_row() {
    let r1cs = exported::<Negated<1>>();
    let broken: Vec<_> = INVALID
        .iter()
        .map(|vector| {
            let (value, negation) = vector.fields();
            let witness = [Fr::one(), value.into(), negation.into()];
            (vector.name, r1cs.first_unsatisfied(&witness))
        })
        .collect();
    assert_eq!(
        broken,
        INVALID
            .iter()
            .map(|vector| (vector.name, Some(0)))
            .collect::<Vec<_>>()
    );
}

struct Tampered;

impl Visit<CircuitVar> for Tampered {
    type Output = (Result<(), ProverRefusal>, Result<(), ProverRefusal>);

    fn visit<F: Fixture<CircuitVar>>(&self, fixture: &F) -> Self::Output {
        let negation = assignment(fixture)[NEGATION_WIRE];
        let tamper = |value: Fr| check_tampered(fixture, NEGATION_WIRE, Field::from(value));
        (tamper(negation), tamper(negation + Fr::one()))
    }
}

#[test]
fn the_proving_rows_accept_the_honest_negation_and_name_the_rule_for_another() {
    assert_eq!(
        per_vector(&VALID, |vector| every_form(&Tampered, vector.fields())),
        expected(&VALID, &form_names(), |_, _| (
            Ok(()),
            Err(breaks_rule(0, RULE))
        ))
    );
}

#[test]
fn no_private_variable_is_free_in_any_form() {
    assert_eq!(
        per_vector(&VALID, |vector| every_form(&FreeVariables, vector.fields())),
        expected(&VALID, &form_names(), |_, _| no_free_variable(1, 2))
    );
}
