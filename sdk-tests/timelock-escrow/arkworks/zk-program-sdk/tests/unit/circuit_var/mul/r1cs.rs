use ark_bn254::Fr;
use ark_ff::One;
use zk_program_sdk::{
    circuit::{CircuitVar, Field},
    ZkCircuit,
};

use super::{
    fixtures::{
        claimed_wire, constant_form_names, constant_forms, every_form, every_form_name,
        variable_form_names, variable_forms, Square, SumTimes, TimesFive, TimesZero,
        UnassertedConstants, UnassertedVariables, Variables, WithConstant, CLAIMED_WIRE, RULE,
        WITNESS_WIRE,
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

const UNLABELLED_ROW_0: ProverRefusal = ("ProverError.ProofInputsBreakRule", Some(0), None);

fn rows(r1cs: R1cs) -> (Vec<Row>, Vec<Row>, Vec<Row>) {
    (r1cs.a, r1cs.b, r1cs.c)
}

fn plus_one(witness: Vec<Fr>, wire: usize) -> Vec<Fr> {
    let value = witness[wire] + Fr::one();
    with_wires(witness, &[(wire, value)])
}

fn is_variable_form(form: &str) -> bool {
    variable_form_names().contains(&form)
}

#[test]
fn a_times_b_exports_exactly_the_golden_rows_and_header() {
    let one = Fr::one();
    assert_eq!(
        exported::<Variables<3>>(),
        R1cs {
            header: R1csHeader::bn254(5, 0, 4, 2),
            a: vec![vec![(one, 1)], vec![(one, 4), (-one, 3)]],
            b: vec![vec![(one, 2)], vec![(one, 0)]],
            c: vec![vec![(one, 4)], vec![]],
            wire_labels: vec![0, 1, 2, 3, 4],
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
fn a_product_of_two_variables_adds_exactly_one_constraint_and_one_variable() {
    let one = Fr::one();
    let (left, right) = (field("3"), field("4"));
    let fixture = UnassertedVariables { left, right };
    assert_eq!(
        (
            exported::<UnassertedVariables>(),
            assignment(&fixture),
            check_constraints(&fixture)
        ),
        (
            R1cs {
                header: R1csHeader::bn254(9, 0, 8, 6),
                a: vec![vec![(one, 1)]; 6],
                b: vec![vec![(one, 2)]; 6],
                c: (3..9).map(|wire| vec![(one, wire)]).collect(),
                wire_labels: (0..9).collect(),
            },
            [
                vec![one, left.into(), right.into()],
                vec![Fr::from(12u64); 6]
            ]
            .concat(),
            Ok(6)
        )
    );
}

#[test]
fn a_product_by_a_constant_adds_no_constraint_and_no_variable() {
    let fixture = UnassertedConstants { left: field("3") };
    assert_eq!(
        (
            exported::<UnassertedConstants>(),
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
fn a_times_a_multiplies_the_variable_by_itself() {
    let one = Fr::one();
    assert_eq!(
        rows(exported::<Square>()),
        (
            vec![vec![(one, 1)], vec![(one, 3), (-one, 2)]],
            vec![vec![(one, 1)], vec![(one, 0)]],
            vec![vec![(one, 3)], vec![]]
        )
    );
}

#[test]
fn a_sum_times_c_inlines_the_sum_into_the_product_row() {
    let one = Fr::one();
    assert_eq!(
        rows(exported::<SumTimes>()),
        (
            vec![vec![(one, 1), (one, 2)], vec![(one, 5), (-one, 4)]],
            vec![vec![(one, 3)], vec![(one, 0)]],
            vec![vec![(one, 5)], vec![]]
        )
    );
}

#[test]
fn a_times_a_constant_scales_the_variable_by_exactly_the_constant() {
    let one = Fr::one();
    let times_zero = (vec![vec![(-one, 2)]], vec![vec![(one, 0)]], vec![vec![]]);
    assert_eq!(
        (
            rows(exported::<TimesFive>()),
            rows(exported::<TimesZero>()),
            rows(exported::<WithConstant<1>>())
        ),
        (
            (
                vec![vec![(Fr::from(5u64), 1), (-one, 2)]],
                vec![vec![(one, 0)]],
                vec![vec![]]
            ),
            times_zero.clone(),
            times_zero
        )
    );
}

#[test]
fn every_valid_vector_checks_two_constraints_in_every_variable_form() {
    assert_eq!(
        per_vector(&VALID, |vector| variable_forms(
            &CheckConstraints,
            vector.fields()
        )),
        expected(&VALID, &variable_form_names(), |_, _| Ok(2))
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
fn the_assignment_is_the_operands_the_claim_then_the_product_witness() {
    assert_eq!(
        per_vector(&VALID, |vector| every_form(&Assignment, vector.fields())),
        expected(&VALID, &every_form_name(), |vector, form| {
            let (left, right, product) = vector.fields();
            if is_variable_form(form) {
                vec![
                    Fr::one(),
                    left.into(),
                    right.into(),
                    product.into(),
                    (left * right).into(),
                ]
            } else {
                vec![Fr::one(), left.into(), product.into()]
            }
        })
    );
}

struct ExportedRows;

impl Visit<CircuitVar> for ExportedRows {
    type Output = [Option<usize>; 3];

    fn visit<F: Fixture<CircuitVar>>(&self, fixture: &F) -> Self::Output {
        let r1cs = exported::<F>();
        let honest = assignment(fixture);
        [
            r1cs.first_unsatisfied(&honest),
            r1cs.first_unsatisfied(&plus_one(honest.clone(), CLAIMED_WIRE)),
            r1cs.first_unsatisfied(&plus_one(honest, WITNESS_WIRE)),
        ]
    }
}

#[test]
fn every_valid_vector_satisfies_every_row_and_each_tampered_wire_breaks_its_row() {
    assert_eq!(
        per_vector(&VALID, |vector| variable_forms(
            &ExportedRows,
            vector.fields()
        )),
        expected(&VALID, &variable_form_names(), |_, _| [
            None,
            Some(1),
            Some(0)
        ])
    );
}

#[test]
fn a_constant_fixed_in_the_circuit_exports_a_row_every_honest_witness_satisfies() {
    let r1cs = exported::<TimesFive>();
    let checked: Vec<_> = VALID
        .iter()
        .map(|vector| {
            let a = field(vector.left);
            let honest = assignment(&TimesFive {
                a,
                product: a * Field::from(5u64),
            });
            (
                vector.name,
                r1cs.first_unsatisfied(&honest),
                r1cs.first_unsatisfied(&plus_one(honest.clone(), 2)),
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
fn every_invalid_vector_breaks_a_row_whichever_product_witness_it_takes() {
    let r1cs = exported::<Variables<3>>();
    let broken: Vec<_> = INVALID
        .iter()
        .map(|vector| {
            let (left, right, product) = vector.fields();
            let witness = |computed: Field| {
                [
                    Fr::one(),
                    left.into(),
                    right.into(),
                    product.into(),
                    computed.into(),
                ]
            };
            (
                vector.name,
                r1cs.first_unsatisfied(&witness(left * right)),
                r1cs.first_unsatisfied(&witness(product)),
            )
        })
        .collect();
    assert_eq!(
        broken,
        INVALID
            .iter()
            .map(|vector| (vector.name, Some(1), Some(0)))
            .collect::<Vec<_>>()
    );
}

struct Tampered;

impl Visit<CircuitVar> for Tampered {
    type Output = (
        Result<(), ProverRefusal>,
        Result<(), ProverRefusal>,
        Option<Result<(), ProverRefusal>>,
    );

    fn visit<F: Fixture<CircuitVar>>(&self, fixture: &F) -> Self::Output {
        let honest = assignment(fixture);
        let claimed = claimed_wire(honest.len());
        let tamper = |wire: usize, value: Fr| check_tampered(fixture, wire, Field::from(value));
        (
            tamper(claimed, honest[claimed]),
            tamper(claimed, honest[claimed] + Fr::one()),
            (claimed == CLAIMED_WIRE)
                .then(|| tamper(WITNESS_WIRE, honest[WITNESS_WIRE] + Fr::one())),
        )
    }
}

#[test]
fn the_proving_rows_name_the_rule_for_a_wrong_claim_and_no_rule_for_a_wrong_witness() {
    assert_eq!(
        per_vector(&VALID, |vector| every_form(&Tampered, vector.fields())),
        expected(&VALID, &every_form_name(), |_, form| {
            if is_variable_form(form) {
                (
                    Ok(()),
                    Err(breaks_rule(1, RULE)),
                    Some(Err(UNLABELLED_ROW_0)),
                )
            } else {
                (Ok(()), Err(breaks_rule(0, RULE)), None)
            }
        })
    );
}

struct UnboundOperands;

impl Visit<CircuitVar> for UnboundOperands {
    type Output = (usize, usize, Vec<usize>, usize);

    fn visit<F: Fixture<CircuitVar>>(&self, fixture: &F) -> Self::Output {
        let report = FreeVariables.visit(fixture);
        (
            report.constraints,
            report.private_variables,
            report.free.iter().map(|free| free.variable).collect(),
            report.tolerated.len(),
        )
    }
}

#[test]
fn no_private_variable_is_free_unless_its_partner_operand_is_zero() {
    let nonzero: Vec<_> = VALID
        .into_iter()
        .filter(|vector| vector.left != "0" && vector.right != "0")
        .collect();
    let zero = |decimal: &str| decimal == "0";
    assert_eq!(
        (
            per_vector(&nonzero, |vector| every_form(
                &FreeVariables,
                vector.fields()
            )),
            per_vector(&VALID, |vector| every_form(
                &UnboundOperands,
                vector.fields()
            )),
        ),
        (
            expected(&nonzero, &every_form_name(), |_, form| {
                if is_variable_form(form) {
                    no_free_variable(2, 4)
                } else {
                    no_free_variable(1, 2)
                }
            }),
            expected(&VALID, &every_form_name(), |vector, form| {
                if is_variable_form(form) {
                    let free = [(0, vector.right), (1, vector.left)]
                        .into_iter()
                        .filter(|(_, partner)| zero(partner))
                        .map(|(variable, _)| variable)
                        .collect();
                    (2, 4, free, 0)
                } else {
                    let free = if zero(vector.right) { vec![0] } else { vec![] };
                    (1, 2, free, 0)
                }
            }),
        )
    );
}
