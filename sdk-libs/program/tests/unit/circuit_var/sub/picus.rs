#![cfg(feature = "external-tools")]

use std::time::Duration;

use zolana_program::circuit::CircuitVar;

use super::{
    fixtures::{
        constant_form_names, every_form, every_form_name, variable_form_names, MinusFive,
        SelfMinusSelf, Unasserted, Variables, WithConstant,
    },
    vectors::VALID,
};
use crate::harness::{
    fixture::{each, export, picus_export, Fixture, PicusExport, Visit, Visited},
    iden3::read_r1cs,
    picus::{promote, verdict_within, Verdict},
    WorkDir,
};

const LIMIT: Duration = Duration::from_secs(120);

fn verdict(work: &WorkDir, name: &str, r1cs: &[u8]) -> Verdict {
    verdict_within(work, name, r1cs, LIMIT)
}

fn last_wire(r1cs: &[u8]) -> usize {
    read_r1cs(r1cs).header.variables - 1
}

fn per_form<T>(visitor: &impl Visit<CircuitVar, Output = T>) -> Visited<T> {
    every_form(visitor, VALID[0].fields())
}

#[test]
fn with_no_gadget_witness_the_picus_export_is_the_snarkjs_export() {
    let mut forms = each(&variable_form_names(), export::<Variables<3>>());
    forms.extend(each(&constant_form_names(), export::<WithConstant<1>>()));
    assert_eq!(
        (
            per_form(&PicusExport),
            picus_export::<Unasserted>(),
            picus_export::<SelfMinusSelf>(),
            picus_export::<MinusFive>(),
        ),
        (
            forms,
            export::<Unasserted>(),
            export::<SelfMinusSelf>(),
            export::<MinusFive>(),
        )
    );
}

struct DifferenceVerdicts<'a>(&'a WorkDir);

impl<C> Visit<C> for DifferenceVerdicts<'_> {
    type Output = (Verdict, Verdict);

    fn visit<F: Fixture<C>>(&self, _fixture: &F) -> (Verdict, Verdict) {
        let r1cs = picus_export::<F>();
        let name = std::any::type_name::<F>().replace(|c: char| !c.is_alphanumeric(), "-");
        (
            verdict(self.0, &name, &r1cs),
            verdict(
                self.0,
                &format!("{name}-difference"),
                &promote(&r1cs, last_wire(&r1cs)),
            ),
        )
    }
}

#[test]
fn picus_finds_every_form_safe_and_the_difference_fixed_by_its_operands() {
    let work = WorkDir::new("sub-picus-difference");
    assert_eq!(
        per_form(&DifferenceVerdicts(&work)),
        each(&every_form_name(), (Verdict::Safe, Verdict::Safe))
    );
}

#[test]
fn picus_finds_a_free_once_a_minus_a_cancels() {
    let work = WorkDir::new("sub-picus-cancel");
    let r1cs = picus_export::<SelfMinusSelf>();
    assert_eq!(
        (
            verdict(&work, "a", &promote(&r1cs, 1)),
            verdict(&work, "difference", &promote(&r1cs, 2)),
            verdict(&work, "minus-five", &{
                let r1cs = picus_export::<MinusFive>();
                promote(&r1cs, last_wire(&r1cs))
            }),
        ),
        (Verdict::Unsafe, Verdict::Safe, Verdict::Safe)
    );
}

#[test]
fn picus_finds_an_operand_free_when_no_difference_is_asserted() {
    let work = WorkDir::new("sub-picus-unasserted");
    let r1cs = picus_export::<Unasserted>();
    assert_eq!(
        (
            verdict(&work, "unasserted", &r1cs),
            verdict(&work, "right", &promote(&r1cs, 2)),
        ),
        (Verdict::Safe, Verdict::Unsafe)
    );
}
