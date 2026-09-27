use std::fmt::Debug;

use ark_bn254::Fr;
use ark_ff::One;
use zk_program_sdk::{
    circuit::Field,
    testing::{check_private_variables, check_tampered, PrivateVariableReport, Tamper},
    ProverError, ProverErrorKind, ZkCircuit,
};

use super::{
    fixtures::{
        constant_form_names, constant_forms, every_form, every_form_name, expected, per_vector,
        variable_form_names, variable_forms, AddThenSubtract, Double, Operands, PlusFive,
        Unasserted, Variables, Visit, WithConstant, RULE,
    },
    vectors::{INVALID, VALID},
};
use crate::harness::{
    field::field,
    iden3::{read_r1cs, read_wtns, R1cs, R1csHeader, Row},
};

type Refusal = (&'static str, Option<usize>, Option<&'static str>);

fn refusal(error: ProverError) -> Refusal {
    match error.kind() {
        ProverErrorKind::ConstraintsDiffer(failed)
        | ProverErrorKind::ProofInputsBreakRule(failed) => (
            error.name(),
            Some(failed.row),
            failed.label.as_ref().map(|label| label.text),
        ),
        _ => (error.name(), None, None),
    }
}

fn exported<F: ZkCircuit>() -> R1cs {
    read_r1cs(&F::export_r1cs().expect("r1cs export"))
}

fn assignment<F: ZkCircuit>(fixture: &F) -> Vec<Fr> {
    read_wtns(&fixture.export_assignment().expect("assignment"))
}

fn rows(r1cs: R1cs) -> (Vec<Row>, Vec<Row>, Vec<Row>) {
    (r1cs.a, r1cs.b, r1cs.c)
}

fn is_variable_form(form: &str) -> bool {
    variable_form_names().contains(&form)
}

#[test]
fn a_plus_b_exports_exactly_the_golden_row_and_header() {
    let one = Fr::one();
    assert_eq!(
        exported::<Variables<3>>(),
        R1cs {
            header: R1csHeader::bn254(4, 0, 3, 1),
            a: vec![vec![(one, 1), (one, 2), (-one, 3)]],
            b: vec![vec![(one, 0)]],
            c: vec![vec![]],
            wire_labels: vec![0, 1, 2, 3],
        }
    );
}

struct Export;

impl Visit for Export {
    type Output = Vec<u8>;

    fn visit<F>(&self, _fixture: F) -> Vec<u8>
    where
        F: ZkCircuit + Copy + Debug,
        F::Circuit: Operands,
    {
        F::export_r1cs().expect("r1cs export")
    }
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
            variable_form_names()
                .into_iter()
                .map(|form| (form, variables.clone()))
                .collect(),
            constant_form_names()
                .into_iter()
                .map(|form| (form, constants.clone()))
                .collect()
        )
    );
}

#[test]
fn adding_allocates_no_variable_and_adds_no_constraint() {
    let fixture = Unasserted {
        left: field("1"),
        right: field("2"),
    };
    assert_eq!(
        (
            exported::<Unasserted>(),
            assignment(&fixture),
            fixture.check_constraints().map_err(refusal)
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
fn a_plus_a_has_coefficient_exactly_two() {
    let one = Fr::one();
    assert_eq!(
        rows(exported::<Double>()),
        (
            vec![vec![(Fr::from(2u64), 1), (-one, 2)]],
            vec![vec![(one, 0)]],
            vec![vec![]]
        )
    );
}

#[test]
fn a_plus_b_minus_b_inlines_to_exactly_a() {
    let one = Fr::one();
    assert_eq!(
        rows(exported::<AddThenSubtract>()),
        (
            vec![vec![(one, 1), (-one, 3)]],
            vec![vec![(one, 0)]],
            vec![vec![]]
        )
    );
}

#[test]
fn a_plus_a_constant_puts_exactly_the_constant_on_variable_zero() {
    let one = Fr::one();
    assert_eq!(
        (
            rows(exported::<PlusFive>()),
            rows(exported::<WithConstant<1>>())
        ),
        (
            (
                vec![vec![(Fr::from(5u64), 0), (one, 1), (-one, 2)]],
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

struct CheckConstraints;

impl Visit for CheckConstraints {
    type Output = Result<usize, Refusal>;

    fn visit<F>(&self, fixture: F) -> Self::Output
    where
        F: ZkCircuit + Copy + Debug,
        F::Circuit: Operands,
    {
        fixture.check_constraints().map_err(refusal)
    }
}

#[test]
fn every_valid_vector_checks_one_constraint_in_every_variable_form() {
    assert_eq!(
        per_vector(&VALID, |fields| variable_forms(&CheckConstraints, fields)),
        expected(&VALID, &variable_form_names(), |_, _| Ok(1))
    );
}

#[test]
fn a_constant_other_than_the_placeholders_builds_a_different_row() {
    assert_eq!(
        per_vector(&VALID, |fields| constant_forms(&CheckConstraints, fields)),
        expected(&VALID, &constant_form_names(), |vector, _| {
            if vector.right == "0" {
                Ok(1)
            } else {
                Err(("ProverError.ConstraintsDiffer", Some(0), Some(RULE)))
            }
        })
    );
}

struct Assignment;

impl Visit for Assignment {
    type Output = Vec<Fr>;

    fn visit<F>(&self, fixture: F) -> Vec<Fr>
    where
        F: ZkCircuit + Copy + Debug,
        F::Circuit: Operands,
    {
        assignment(&fixture)
    }
}

#[test]
fn the_assignment_is_the_constant_one_then_the_variable_inputs() {
    assert_eq!(
        per_vector(&VALID, |fields| every_form(&Assignment, fields)),
        expected(&VALID, &every_form_name(), |vector, form| {
            let (left, right, sum) = vector.fields();
            if is_variable_form(form) {
                vec![Fr::one(), left.into(), right.into(), sum.into()]
            } else {
                vec![Fr::one(), left.into(), sum.into()]
            }
        })
    );
}

struct ExportedRow;

impl Visit for ExportedRow {
    type Output = (Option<usize>, Option<usize>);

    fn visit<F>(&self, fixture: F) -> Self::Output
    where
        F: ZkCircuit + Copy + Debug,
        F::Circuit: Operands,
    {
        let r1cs = exported::<F>();
        let honest = assignment(&fixture);
        let mut tampered = honest.clone();
        if let Some(sum) = tampered.last_mut() {
            *sum += Fr::one();
        }
        (
            r1cs.first_unsatisfied(&honest),
            r1cs.first_unsatisfied(&tampered),
        )
    }
}

#[test]
fn every_valid_vector_satisfies_the_row_and_a_tampered_sum_breaks_it() {
    assert_eq!(
        per_vector(&VALID, |fields| variable_forms(&ExportedRow, fields)),
        expected(&VALID, &variable_form_names(), |_, _| (None, Some(0)))
    );
}

#[test]
fn a_constant_fixed_in_the_circuit_exports_a_row_every_honest_witness_satisfies() {
    let r1cs = exported::<PlusFive>();
    let checked: Vec<_> = VALID
        .iter()
        .map(|vector| {
            let a = field(vector.left);
            let honest = assignment(&PlusFive {
                a,
                sum: a + Field::from(5u64),
            });
            let mut tampered = honest.clone();
            if let Some(sum) = tampered.last_mut() {
                *sum += Fr::one();
            }
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
            let (left, right, sum) = vector.fields();
            let witness = [Fr::one(), left.into(), right.into(), sum.into()];
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

impl Visit for Tampered {
    type Output = (Result<(), Refusal>, Result<(), Refusal>);

    fn visit<F>(&self, fixture: F) -> Self::Output
    where
        F: ZkCircuit + Copy + Debug,
        F::Circuit: Operands,
    {
        let honest = assignment(&fixture);
        let sum = *honest.last().expect("sum");
        let tamper = |value: Fr| {
            check_tampered(
                &fixture,
                Tamper::PrivateVariable {
                    index: honest.len() - 2,
                    value: Field::from(value),
                },
            )
            .map_err(refusal)
        };
        (tamper(sum), tamper(sum + Fr::one()))
    }
}

#[test]
fn the_proving_rows_accept_the_honest_sum_and_name_the_rule_for_another() {
    assert_eq!(
        per_vector(&VALID, |fields| every_form(&Tampered, fields)),
        expected(&VALID, &every_form_name(), |_, _| (
            Ok(()),
            Err(("ProverError.ProofInputsBreakRule", Some(0), Some(RULE)))
        ))
    );
}

struct FreeVariables;

impl Visit for FreeVariables {
    type Output = PrivateVariableReport;

    fn visit<F>(&self, fixture: F) -> PrivateVariableReport
    where
        F: ZkCircuit + Copy + Debug,
        F::Circuit: Operands,
    {
        check_private_variables(&fixture).expect("private variable report")
    }
}

#[test]
fn no_private_variable_is_free_in_any_form() {
    assert_eq!(
        per_vector(&VALID, |fields| every_form(&FreeVariables, fields)),
        expected(&VALID, &every_form_name(), |_, form| {
            PrivateVariableReport {
                constraints: 1,
                private_variables: if is_variable_form(form) { 3 } else { 2 },
                free: vec![],
                tolerated: vec![],
            }
        })
    );
}

#[test]
fn a_constraint_only_circuit_has_no_public_hash_to_tamper() {
    let (left, right, sum) = VALID[1].fields();
    assert_eq!(
        check_tampered(
            &Variables::<3> { left, right, sum },
            Tamper::PublicHash(Field::from(1u64))
        )
        .map_err(refusal),
        Err(("ProverError.WrongPublicInputCount", None, None))
    );
}
