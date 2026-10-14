#![cfg(feature = "external-tools")]

use zolana_program::circuit::CircuitVar;

use super::{
    fixtures::{
        constant_form_names, every_form, every_form_name, variable_form_names, AddThenSubtract,
        Double, PlusFive, Unasserted, Variables, WithConstant,
    },
    vectors::VALID,
};
use crate::harness::{
    fixture::{each, export, picus_export, Fixture, PicusExport, Visit, Visited},
    iden3::read_r1cs,
    picus::{promote, verdict, Verdict},
    WorkDir,
};

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
            picus_export::<Double>(),
            picus_export::<AddThenSubtract>(),
            picus_export::<PlusFive>(),
        ),
        (
            forms,
            export::<Unasserted>(),
            export::<Double>(),
            export::<AddThenSubtract>(),
            export::<PlusFive>(),
        )
    );
}

struct SumVerdicts<'a>(&'a WorkDir);

impl<C> Visit<C> for SumVerdicts<'_> {
    type Output = (Verdict, Verdict);

    fn visit<F: Fixture<C>>(&self, _fixture: &F) -> (Verdict, Verdict) {
        let r1cs = picus_export::<F>();
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
        each(&every_form_name(), (Verdict::Safe, Verdict::Safe))
    );
}

#[test]
fn picus_finds_the_sum_of_a_plus_a_and_a_plus_five_fixed() {
    let work = WorkDir::new("picus-double");
    let sum_of =
        |name: &str, r1cs: Vec<u8>| verdict(&work, name, &promote(&r1cs, last_wire(&r1cs)));
    assert_eq!(
        (
            sum_of("double", picus_export::<Double>()),
            sum_of("plus-five", picus_export::<PlusFive>()),
        ),
        (Verdict::Safe, Verdict::Safe)
    );
}

#[test]
fn picus_finds_b_free_once_a_plus_b_minus_b_inlines_to_a() {
    let work = WorkDir::new("picus-cancel");
    let r1cs = picus_export::<AddThenSubtract>();
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
    let r1cs = picus_export::<Unasserted>();
    assert_eq!(
        (
            verdict(&work, "unasserted", &r1cs),
            verdict(&work, "right", &promote(&r1cs, 2)),
        ),
        (Verdict::Safe, Verdict::Unsafe)
    );
}
