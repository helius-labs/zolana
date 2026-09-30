use ark_bn254::Fr;
use ark_ff::One;
use zolana_program::{
    circuit::{CircuitVar, Field},
    ZkCircuit,
};

use super::{
    fixtures::{
        constant_form_names, constant_forms, every_form, every_form_name, variable_form_names,
        variable_forms, MinusFive, SelfMinusSelf, Unasserted, Variables, WithConstant, RULE,
    },
    vectors::{INVALID, VALID},
};
use crate::harness::{
    field::field,
    fixture::{
        assignment, breaks_rule, check_constraints, check_tampered, constraints_differ, each,
        expected, exported, no_free_variable, per_vector, with_wires, Assignment, CheckConstraints,
        Export, Fixture, FreeVariables, ProverRefusal, Visit,
    },
    iden3::{R1cs, R1csHeader, Row},
};

fn rows(r1cs: R1cs) -> (Vec<Row>, Vec<Row>, Vec<Row>) {
    (r1cs.a, r1cs.b, r1cs.c)
}

fn tampered_difference(witness: Vec<Fr>) -> Vec<Fr> {
    let (wire, difference) = (witness.len() - 1, *witness.last().expect("difference"));
    with_wires(witness, &[(wire, difference + Fr::one())])
}

fn is_variable_form(form: &str) -> bool {
    variable_form_names().contains(&form)
}

#[test]
fn a_minus_b_exports_exactly_the_golden_row_and_header() {
    let one = Fr::one();
    assert_eq!(
        exported::<Variables<3>>(),
        R1cs {
            header: R1csHeader::bn254(4, 0, 3, 1),
            a: vec![vec![(one, 1), (-one, 2), (-one, 3)]],
            b: vec![vec![(one, 0)]],
            c: vec![vec![]],
            wire_labels: vec![0, 1, 2, 3],
        }
    );
}

#[test]
fn every_form_of_one_operand_kind_exports_byte_identical_r1cs() {
    let fields = VALID[0].fields();
    let variables = Variables::<3>::export_r1cs().expect("r1cs export");
    let constants = WithConstant::<1>::export_r1cs().expect("r1cs export");
    assert_eq!(
        (
            variable_forms(&Export, fields),
            constant_forms(&Export, fields)
        ),
        (
            each(&variable_form_names(), variables),
            each(&constant_form_names(), constants)
        )
    );
}

#[test]
fn subtracting_allocates_no_variable_and_adds_no_constraint() {
    let fixture = Unasserted {
        left: field("1"),
        right: field("2"),
    };
    assert_eq!(
        (
            exported::<Unasserted>(),
            assignment(&fixture),
            check_constraints(&fixture)
        ),
        (
            R1cs {
                header: R1csHeader::bn254(3, 0, 2, 0),
                a: vec![],
                b: vec![],
                c: vec![],
                wire_labels: vec![0, 1, 2],
            },
            vec![Fr::one(), Fr::from(1u64), Fr::from(2u64)],
            Ok(0)
        )
    );
}

#[test]
fn a_minus_a_cancels_to_no_entry_for_a() {
    let one = Fr::one();
    assert_eq!(
        rows(exported::<SelfMinusSelf>()),
        (vec![vec![(-one, 2)]], vec![vec![(one, 0)]], vec![vec![]])
    );
}

#[test]
fn a_minus_a_constant_puts_exactly_minus_the_constant_on_variable_zero() {
    let one = Fr::one();
    assert_eq!(
        (
            rows(exported::<MinusFive>()),
            rows(exported::<WithConstant<1>>())
        ),
        (
            (
                vec![vec![(-Fr::from(5u64), 0), (one, 1), (-one, 2)]],
                vec![vec![(one, 0)]],
                vec![vec![]]
            ),
            (
                vec![vec![(one, 1), (-one, 2)]],
                vec![vec![(one, 0)]],
                vec![vec![]]
            )
        )
    );
}

#[test]
fn every_valid_vector_checks_one_constraint_in_every_variable_form() {
    assert_eq!(
        per_vector(&VALID, |vector| variable_forms(
            &CheckConstraints,
            vector.fields()
        )),
        expected(&VALID, &variable_form_names(), |_, _| Ok(1))
    );
}

#[test]
fn a_constant_other_than_the_placeholders_builds_a_different_row() {
    assert_eq!(
        per_vector(&VALID, |vector| constant_forms(
            &CheckConstraints,
            vector.fields()
        )),
        expected(&VALID, &constant_form_names(), |vector, _| {
            if vector.right == "0" {
                Ok(1)
            } else {
                Err(constraints_differ(0, RULE))
            }
        })
    );
}

#[test]
fn the_assignment_is_the_constant_one_then_the_variable_inputs() {
    assert_eq!(
        per_vector(&VALID, |vector| every_form(&Assignment, vector.fields())),
        expected(&VALID, &every_form_name(), |vector, form| {
            let (left, right, difference) = vector.fields();
            if is_variable_form(form) {
                vec![Fr::one(), left.into(), right.into(), difference.into()]
            } else {
                vec![Fr::one(), left.into(), difference.into()]
            }
        })
    );
}

struct ExportedRow;

impl Visit<CircuitVar> for ExportedRow {
    type Output = (Option<usize>, Option<usize>);

    fn visit<F: Fixture<CircuitVar>>(&self, fixture: &F) -> Self::Output {
        let r1cs = exported::<F>();
        let honest = assignment(fixture);
        let tampered = tampered_difference(honest.clone());
        (
            r1cs.first_unsatisfied(&honest),
            r1cs.first_unsatisfied(&tampered),
        )
    }
}

#[test]
fn every_valid_vector_satisfies_the_row_and_a_tampered_difference_breaks_it() {
    assert_eq!(
        per_vector(&VALID, |vector| variable_forms(
            &ExportedRow,
            vector.fields()
        )),
        expected(&VALID, &variable_form_names(), |_, _| (None, Some(0)))
    );
}

#[test]
fn a_constant_fixed_in_the_circuit_exports_a_row_every_honest_witness_satisfies() {
    let r1cs = exported::<MinusFive>();
    let checked: Vec<_> = VALID
        .iter()
        .map(|vector| {
            let a = field(vector.left);
            let honest = assignment(&MinusFive {
                a,
                difference: a - Field::from(5u64),
            });
            let tampered = tampered_difference(honest.clone());
            (
                vector.name,
                r1cs.first_unsatisfied(&honest),
                r1cs.first_unsatisfied(&tampered),
            )
        })
        .collect();
    assert_eq!(
        checked,
        VALID
            .iter()
            .map(|vector| (vector.name, None, Some(0)))
            .collect::<Vec<_>>()
    );
}

#[test]
fn every_invalid_vector_breaks_the_row() {
    let r1cs = exported::<Variables<3>>();
    let broken: Vec<_> = INVALID
        .iter()
        .map(|vector| {
            let (left, right, difference) = vector.fields();
            let witness = [Fr::one(), left.into(), right.into(), difference.into()];
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
        let honest = assignment(fixture);
        let wire = honest.len() - 1;
        let difference = *honest.last().expect("difference");
        let tamper = |value: Fr| check_tampered(fixture, wire, Field::from(value));
        (tamper(difference), tamper(difference + Fr::one()))
    }
}

#[test]
fn the_proving_rows_accept_the_honest_difference_and_name_the_rule_for_another() {
    assert_eq!(
        per_vector(&VALID, |vector| every_form(&Tampered, vector.fields())),
        expected(&VALID, &every_form_name(), |_, _| (
            Ok(()),
            Err(breaks_rule(0, RULE))
        ))
    );
}

#[test]
fn no_private_variable_is_free_in_any_form() {
    assert_eq!(
        per_vector(&VALID, |vector| every_form(&FreeVariables, vector.fields())),
        expected(&VALID, &every_form_name(), |_, form| {
            no_free_variable(1, if is_variable_form(form) { 3 } else { 2 })
        })
    );
}
