#![cfg(feature = "external-tools")]

use std::time::Duration;

use zolana_program::circuit::CircuitVar;

use super::{
    fixtures::{
        claimed_wire, constant_form_names, every_form, every_form_name, variable_form_names,
        Square, SumTimes, TimesZero, UnassertedConstants, UnassertedVariables, Variables,
        WithConstant,
    },
    vectors::VALID,
};
use crate::harness::{
    fixture::{assignment, each, export, picus_export, Fixture, PicusExport, Visit, Visited},
    iden3::{read_r1cs, R1csHeader},
    picus::{picus_wire, promote, verdict_within, Verdict},
    WorkDir,
};

const LIMIT: Duration = Duration::from_secs(120);

fn verdict(work: &WorkDir, name: &str, r1cs: &[u8]) -> Verdict {
    verdict_within(work, name, r1cs, LIMIT)
}

fn per_form<T>(visitor: &impl Visit<CircuitVar, Output = T>) -> Visited<T> {
    every_form(visitor, VALID[0].fields())
}

fn promoted<F: zolana_program::ZkCircuit>(variable: usize) -> Vec<u8> {
    let r1cs = picus_export::<F>();
    promote(&r1cs, picus_wire(&r1cs, variable))
}

#[test]
fn the_picus_export_makes_the_product_witness_its_only_output() {
    let variables = read_r1cs(&picus_export::<Variables<3>>());
    let mut forms = each(&variable_form_names(), picus_export::<Variables<3>>());
    forms.extend(each(&constant_form_names(), export::<WithConstant<1>>()));
    assert_eq!(
        (
            variables.header,
            variables.wire_labels,
            per_form(&PicusExport),
            picus_export::<UnassertedConstants>(),
        ),
        (
            R1csHeader {
                public_outputs: 1,
                ..R1csHeader::bn254(5, 0, 3, 2)
            },
            vec![0, 4, 1, 2, 3],
            forms,
            export::<UnassertedConstants>(),
        )
    );
}

struct ProductVerdicts<'a>(&'a WorkDir);

impl<C> Visit<C> for ProductVerdicts<'_> {
    type Output = (Verdict, Verdict);

    fn visit<F: Fixture<C>>(&self, fixture: &F) -> (Verdict, Verdict) {
        let name = std::any::type_name::<F>().replace(|c: char| !c.is_alphanumeric(), "-");
        let claimed = claimed_wire(assignment(fixture).len());
        (
            verdict(self.0, &name, &picus_export::<F>()),
            verdict(self.0, &format!("{name}-product"), &promoted::<F>(claimed)),
        )
    }
}

#[test]
fn picus_finds_every_form_safe_and_the_product_fixed_by_its_operands() {
    let work = WorkDir::new("mul-picus-product");
    assert_eq!(
        per_form(&ProductVerdicts(&work)),
        each(&every_form_name(), (Verdict::Safe, Verdict::Safe))
    );
}

#[test]
fn picus_finds_the_square_and_the_product_of_a_sum_fixed() {
    let work = WorkDir::new("mul-picus-square");
    assert_eq!(
        (
            verdict(&work, "square", &promoted::<Square>(2)),
            verdict(&work, "sum-times", &promoted::<SumTimes>(4)),
        ),
        (Verdict::Safe, Verdict::Safe)
    );
}

#[test]
fn picus_finds_a_free_once_times_zero_drops_it() {
    let work = WorkDir::new("mul-picus-zero");
    assert_eq!(
        (
            verdict(&work, "a", &promoted::<TimesZero>(1)),
            verdict(&work, "product", &promoted::<TimesZero>(2)),
        ),
        (Verdict::Unsafe, Verdict::Safe)
    );
}

#[test]
fn picus_finds_an_operand_free_when_no_product_is_asserted() {
    let work = WorkDir::new("mul-picus-unasserted");
    assert_eq!(
        (
            verdict(&work, "unasserted", &picus_export::<UnassertedVariables>()),
            verdict(&work, "right", &promoted::<UnassertedVariables>(2)),
            verdict(&work, "scaled", &promoted::<UnassertedConstants>(1)),
        ),
        (Verdict::Safe, Verdict::Unsafe, Verdict::Unsafe)
    );
}
