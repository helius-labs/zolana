#![cfg(feature = "external-tools")]

use std::fmt::Debug;

use zk_program_sdk::ZkCircuit;

use super::{
    fixtures::{
        constant_form_names, every_form, every_form_name, variable_form_names, AddThenSubtract,
        Double, Operands, PlusFive, Unasserted, Variables, Visit, Visited, WithConstant,
    },
    vectors::VALID,
};
use crate::harness::{
    iden3::read_r1cs,
    picus::{promote, verdict, Verdict},
    WorkDir,
};

fn picus_r1cs<F: ZkCircuit>() -> Vec<u8> {
    F::export_picus_r1cs().expect("picus r1cs export")
}

fn last_wire(r1cs: &[u8]) -> usize {
    read_r1cs(r1cs).header.variables - 1
}

fn per_form<T>(visitor: &impl Visit<Output = T>) -> Visited<T> {
    every_form(visitor, VALID[0].fields())
}

fn each_form<T: Clone>(value: T) -> Visited<T> {
    every_form_name()
        .into_iter()
        .map(|form| (form, value.clone()))
        .collect()
}

struct Exports;

impl Visit for Exports {
    type Output = Vec<u8>;

    fn visit<F>(&self, _fixture: F) -> Vec<u8>
    where
        F: ZkCircuit + Copy + Debug,
        F::Circuit: Operands,
    {
        picus_r1cs::<F>()
    }
}

fn snarkjs_r1cs<F: ZkCircuit>() -> Vec<u8> {
    F::export_r1cs().expect("r1cs export")
}

#[test]
fn with_no_gadget_witness_the_picus_export_is_the_snarkjs_export() {
    let (variables, constants) = (
        snarkjs_r1cs::<Variables<3>>(),
        snarkjs_r1cs::<WithConstant<1>>(),
    );
    let mut forms: Visited<Vec<u8>> = variable_form_names()
        .into_iter()
        .map(|form| (form, variables.clone()))
        .collect();
    forms.extend(
        constant_form_names()
            .into_iter()
            .map(|form| (form, constants.clone())),
    );
    assert_eq!(
        (
            per_form(&Exports),
            picus_r1cs::<Unasserted>(),
            picus_r1cs::<Double>(),
            picus_r1cs::<AddThenSubtract>(),
            picus_r1cs::<PlusFive>(),
        ),
        (
            forms,
            snarkjs_r1cs::<Unasserted>(),
            snarkjs_r1cs::<Double>(),
            snarkjs_r1cs::<AddThenSubtract>(),
            snarkjs_r1cs::<PlusFive>(),
        )
    );
}

struct SumVerdicts<'a>(&'a WorkDir);

impl Visit for SumVerdicts<'_> {
    type Output = (Verdict, Verdict);

    fn visit<F>(&self, _fixture: F) -> (Verdict, Verdict)
    where
        F: ZkCircuit + Copy + Debug,
        F::Circuit: Operands,
    {
        let r1cs = picus_r1cs::<F>();
        let name = std::any::type_name::<F>().replace(|c: char| !c.is_alphanumeric(), "-");
        (
            verdict(self.0, &name, &r1cs),
            verdict(
                self.0,
                &format!("{name}-sum"),
                &promote(&r1cs, last_wire(&r1cs)),
            ),
        )
    }
}

#[test]
fn picus_finds_every_form_safe_and_the_sum_fixed_by_its_operands() {
    let work = WorkDir::new("picus-sum");
    assert_eq!(
        per_form(&SumVerdicts(&work)),
        each_form((Verdict::Safe, Verdict::Safe))
    );
}

#[test]
fn picus_finds_the_sum_of_a_plus_a_and_a_plus_five_fixed() {
    let work = WorkDir::new("picus-double");
    let sum_of =
        |name: &str, r1cs: Vec<u8>| verdict(&work, name, &promote(&r1cs, last_wire(&r1cs)));
    assert_eq!(
        (
            sum_of("double", picus_r1cs::<Double>()),
            sum_of("plus-five", picus_r1cs::<PlusFive>()),
        ),
        (Verdict::Safe, Verdict::Safe)
    );
}

#[test]
fn picus_finds_b_free_once_a_plus_b_minus_b_inlines_to_a() {
    let work = WorkDir::new("picus-cancel");
    let r1cs = picus_r1cs::<AddThenSubtract>();
    assert_eq!(
        (
            verdict(&work, "a", &promote(&r1cs, 1)),
            verdict(&work, "b", &promote(&r1cs, 2)),
            verdict(&work, "sum", &promote(&r1cs, 3)),
        ),
        (Verdict::Safe, Verdict::Unsafe, Verdict::Safe)
    );
}

#[test]
fn picus_finds_an_operand_free_when_no_sum_is_asserted() {
    let work = WorkDir::new("picus-unasserted");
    let r1cs = picus_r1cs::<Unasserted>();
    assert_eq!(
        (
            verdict(&work, "unasserted", &r1cs),
            verdict(&work, "right", &promote(&r1cs, 2)),
        ),
        (Verdict::Safe, Verdict::Unsafe)
    );
}
