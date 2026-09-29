#![cfg(feature = "external-tools")]

use std::time::Duration;

use zk_program_sdk::circuit::{CircuitVar, Field};

use super::{
    external::{compile, GATE_REFERENCES},
    fixtures::{
        constant_form_names, every_constant_form, AssertEqualIf, AssertedBinary, AssertedUnary,
        Choose, Converted, Fold, Not, Variables, ALL, ANY, GATES,
    },
};
use crate::harness::{
    equivalence::picus_verdicts,
    fixture::{each, export, picus_export, Fixture, Refusal, Visit, Visited},
    iden3::read_r1cs,
    picus::{picus_wire, promote_all, verdict_within, Verdict},
    WorkDir,
};

const LIMIT: Duration = Duration::from_secs(120);

fn gate_verdicts<const GATE: usize>(work: &WorkDir) -> (&'static str, (Verdict, Verdict)) {
    let compiled = compile(GATE_REFERENCES[GATE]);
    let out = compiled.wire("main.out");
    let name = GATES[GATE].name;
    (
        name,
        picus_verdicts::<Variables<GATE>>(work, name, &[3], &compiled, &[out], LIMIT),
    )
}

#[test]
fn picus_finds_every_gate_output_fixed_by_its_operands_in_the_sdk_and_in_circom() {
    let work = WorkDir::new("picus-bool-gates");
    let not = compile("bool/circom/not.circom");
    assert_eq!(
        (
            [
                gate_verdicts::<0>(&work),
                gate_verdicts::<1>(&work),
                gate_verdicts::<2>(&work),
                gate_verdicts::<3>(&work),
                gate_verdicts::<4>(&work),
                gate_verdicts::<5>(&work),
            ],
            picus_verdicts::<Not>(&work, "not", &[2], &not, &[not.wire("main.out")], LIMIT),
        ),
        (
            GATES.map(|gate| (gate.name, (Verdict::Safe, Verdict::Safe))),
            (Verdict::Safe, Verdict::Safe),
        )
    );
}

#[test]
fn picus_finds_every_fold_and_select_output_fixed_in_the_sdk_and_in_circom() {
    let work = WorkDir::new("picus-bool-folds");
    let reference = |relative: &str| {
        let compiled = compile(relative);
        let out = compiled.wire("main.out");
        (compiled, out)
    };
    let (all, all_out) = reference("bool/circom/multi_and.circom");
    let (any, any_out) = reference("bool/circom/any.circom");
    let (select, select_out) = reference("bool/circom/select.circom");
    assert_eq!(
        [
            picus_verdicts::<Fold<ALL, 3>>(&work, "all", &[4], &all, &[all_out], LIMIT),
            picus_verdicts::<Fold<ANY, 3>>(&work, "any", &[4], &any, &[any_out], LIMIT),
            picus_verdicts::<Choose<0>>(&work, "select", &[4], &select, &[select_out], LIMIT),
        ],
        [(Verdict::Safe, Verdict::Safe); 3]
    );
}

#[test]
fn picus_finds_the_flag_of_assert_true_if_free_in_the_sdk_and_in_circom() {
    let work = WorkDir::new("picus-bool-assert-true-if");
    let compiled = compile("bool/circom/assert_true_if.circom");
    assert_eq!(
        [
            picus_verdicts::<AssertedBinary<0>>(
                &work,
                "flag",
                &[1],
                &compiled,
                &[compiled.wire("main.a")],
                LIMIT
            ),
            picus_verdicts::<AssertedBinary<0>>(
                &work,
                "condition",
                &[2],
                &compiled,
                &[compiled.wire("main.b")],
                LIMIT
            ),
        ],
        [(Verdict::Unsafe, Verdict::Unsafe); 2]
    );
}

fn sdk_verdict<C, F: Fixture<C>>(work: &WorkDir, name: &str, outputs: &[usize]) -> Verdict {
    let picus = picus_export::<F>();
    let wires: Vec<usize> = outputs
        .iter()
        .map(|variable| picus_wire(&picus, *variable))
        .collect();
    verdict_within(work, name, &promote_all(&picus, &wires), LIMIT)
}

#[test]
fn picus_finds_exactly_the_operands_an_assertion_fixes() {
    let work = WorkDir::new("picus-bool-assertions");
    assert_eq!(
        [
            sdk_verdict::<(), AssertedUnary<0>>(&work, "assert-true", &[1]),
            sdk_verdict::<(), AssertedUnary<1>>(&work, "assert-false", &[1]),
            sdk_verdict::<(), AssertedBinary<1>>(&work, "assert-equal", &[2]),
            sdk_verdict::<(), AssertedBinary<2>>(&work, "assert-not-equal", &[2]),
            sdk_verdict::<(), AssertEqualIf>(&work, "assert-equal-if", &[2]),
        ],
        [
            Verdict::Safe,
            Verdict::Safe,
            Verdict::Safe,
            Verdict::Safe,
            Verdict::Unsafe
        ]
    );
}

struct OutputVerdict<'a>(&'a WorkDir, usize);

impl Visit<Result<CircuitVar, Refusal>> for OutputVerdict<'_> {
    type Output = Verdict;

    fn visit<F: Fixture<Result<CircuitVar, Refusal>>>(&self, _fixture: &F) -> Verdict {
        let name = std::any::type_name::<F>().replace(|c: char| !c.is_alphanumeric(), "-");
        sdk_verdict::<Result<CircuitVar, Refusal>, F>(self.0, &name, &[self.1])
    }
}

#[test]
fn picus_finds_every_conversion_and_constant_operand_output_fixed() {
    let work = WorkDir::new("picus-bool-linear");
    let zero = Field::from(0u64);
    assert_eq!(
        (
            sdk_verdict::<(), Converted<0>>(&work, "converted", &[2]),
            [
                sdk_verdict::<(), Fold<ALL, 0>>(&work, "all-0", &[1]),
                sdk_verdict::<(), Fold<ANY, 1>>(&work, "any-1", &[2]),
            ],
            every_constant_form(&OutputVerdict(&work, 2), zero, |_, _| zero),
        ),
        (
            Verdict::Safe,
            [Verdict::Safe, Verdict::Safe],
            GATES
                .iter()
                .map(|gate| (gate.name, each(&constant_form_names(), Verdict::Safe)))
                .collect::<Visited<_>>(),
        )
    );
}

#[test]
fn the_picus_export_moves_exactly_the_gadget_witnesses_to_the_outputs_and_the_hint_last() {
    let labels = |r1cs: Vec<u8>| {
        let r1cs = read_r1cs(&r1cs);
        (r1cs.header.public_outputs, r1cs.wire_labels)
    };
    assert_eq!(
        (
            [
                picus_export::<Not>() == export::<Not>(),
                picus_export::<Converted<0>>() == export::<Converted<0>>(),
                picus_export::<AssertedBinary<1>>() == export::<AssertedBinary<1>>(),
                picus_export::<AssertEqualIf>() == export::<AssertEqualIf>(),
            ],
            labels(picus_export::<Variables<0>>()),
            labels(picus_export::<Choose<0>>()),
            labels(picus_export::<Fold<ALL, 3>>()),
        ),
        (
            [true; 4],
            (1, vec![0, 4, 1, 2, 3]),
            (1, vec![0, 5, 1, 2, 3, 4]),
            (1, vec![0, 5, 1, 2, 3, 4, 6]),
        )
    );
}
