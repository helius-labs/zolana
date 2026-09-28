#![cfg(feature = "external-tools")]
use super::{external::compiled, fixtures::*};
use crate::{
    harness::{picus::Verdict, WorkDir},
    uint::picus_form::claim_verdicts,
};
use std::time::Duration;
const LIMIT: Duration = Duration::from_secs(20);

#[test]
fn picus_checks_relation_outputs_with_a_bounded_solver_budget() {
    let work = WorkDir::new("uint-relations-picus");
    let claim = ["main.claimed"];
    let verdicts = [
        (
            "less",
            claim_verdicts::<Compare<4, 0>>(
                &work,
                "less",
                &[3],
                &compiled("compare_4_0"),
                &claim,
                LIMIT,
            ),
        ),
        (
            "less-equal",
            claim_verdicts::<Compare<4, 1>>(
                &work,
                "less-equal",
                &[3],
                &compiled("compare_4_1"),
                &claim,
                LIMIT,
            ),
        ),
        (
            "min",
            claim_verdicts::<Compare<4, 2>>(
                &work,
                "min",
                &[3],
                &compiled("compare_4_2"),
                &claim,
                LIMIT,
            ),
        ),
        (
            "max",
            claim_verdicts::<Compare<4, 3>>(
                &work,
                "max",
                &[3],
                &compiled("compare_4_3"),
                &claim,
                LIMIT,
            ),
        ),
        (
            "equal",
            claim_verdicts::<Compare<4, 5>>(
                &work,
                "equal",
                &[3],
                &compiled("compare_4_5"),
                &claim,
                LIMIT,
            ),
        ),
        (
            "selection",
            claim_verdicts::<Selection<4>>(
                &work,
                "selection",
                &[4],
                &compiled("selection_4"),
                &claim,
                LIMIT,
            ),
        ),
        (
            "zero",
            claim_verdicts::<Zero<4>>(&work, "zero", &[2], &compiled("zero_4"), &claim, LIMIT),
        ),
        (
            "division",
            claim_verdicts::<Division<4, 4, 4>>(
                &work,
                "division",
                &[3, 4],
                &compiled("division_4"),
                &["main.quotient", "main.remainder"],
                LIMIT,
            ),
        ),
    ];
    for (name, (sdk, circom)) in verdicts {
        eprintln!("Uint Picus {name}: SDK={sdk:?}, circom={circom:?}");
        assert_ne!(sdk, Verdict::Unsafe, "SDK {name}");
        assert_ne!(circom, Verdict::Unsafe, "circom {name}");
    }
}
