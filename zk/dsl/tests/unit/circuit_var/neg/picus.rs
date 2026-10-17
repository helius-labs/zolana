#![cfg(feature = "external-tools")]

use std::time::Duration;

use super::{
    fixtures::{every_form, form_names, DoubleNegation, Negated, PlusNegation, Unasserted},
    vectors::VALID,
};
use crate::harness::{
    fixture::{each, export, picus_export, Fixture, PicusExport, Visit},
    picus::{promote, verdict_within, Verdict},
    WorkDir,
};

const LIMIT: Duration = Duration::from_secs(120);

fn verdict(work: &WorkDir, name: &str, r1cs: &[u8]) -> Verdict {
    verdict_within(work, name, r1cs, LIMIT)
}

const NEGATION_WIRE: usize = 2;

#[test]
fn with_no_gadget_witness_the_picus_export_is_the_snarkjs_export() {
    assert_eq!(
        (
            every_form(&PicusExport, VALID[0].fields()),
            picus_export::<Unasserted>(),
            picus_export::<DoubleNegation>(),
            picus_export::<PlusNegation>(),
        ),
        (
            each(&form_names(), export::<Negated<1>>()),
            export::<Unasserted>(),
            export::<DoubleNegation>(),
            export::<PlusNegation>(),
        )
    );
}

struct NegationVerdicts<'a>(&'a WorkDir);

impl<C> Visit<C> for NegationVerdicts<'_> {
    type Output = (Verdict, Verdict, Verdict);

    fn visit<F: Fixture<C>>(&self, _fixture: &F) -> Self::Output {
        let r1cs = picus_export::<F>();
        let name = std::any::type_name::<F>().replace(|c: char| !c.is_alphanumeric(), "-");
        (
            verdict(self.0, &name, &r1cs),
            verdict(
                self.0,
                &format!("{name}-negation"),
                &promote(&r1cs, NEGATION_WIRE),
            ),
            verdict(self.0, &format!("{name}-value"), &promote(&r1cs, 1)),
        )
    }
}

#[test]
fn picus_finds_the_negation_and_the_value_each_fixed_by_the_other() {
    let work = WorkDir::new("neg-picus");
    assert_eq!(
        (
            every_form(&NegationVerdicts(&work), VALID[0].fields()),
            NegationVerdicts(&work).visit(&DoubleNegation {
                value: VALID[0].fields().0,
                negation: VALID[0].fields().1,
            }),
        ),
        (
            each(&form_names(), (Verdict::Safe, Verdict::Safe, Verdict::Safe)),
            (Verdict::Safe, Verdict::Safe, Verdict::Safe),
        )
    );
}

#[test]
fn picus_finds_the_value_free_once_a_plus_minus_a_cancels() {
    let work = WorkDir::new("neg-picus-cancel");
    let r1cs = picus_export::<PlusNegation>();
    assert_eq!(
        (
            verdict(&work, "value", &promote(&r1cs, 1)),
            verdict(&work, "negation", &promote(&r1cs, NEGATION_WIRE)),
        ),
        (Verdict::Unsafe, Verdict::Safe)
    );
}
