#![cfg(feature = "external-tools")]
use super::fixtures::{IsEqual, Selected};
use crate::harness::{circomlib, equivalence::picus_verdicts, picus::Verdict, WorkDir};
use std::time::Duration;
#[test]
fn picus_checks_equality_and_selection_with_bounded_timeouts() {
    let work = WorkDir::new("bytes-ops-picus");
    let equal = circomlib::compile("bytes/ops/is_equal.circom");
    let select = circomlib::compile("bytes/ops/select.circom");
    let outputs: Vec<_> = (0..32)
        .map(|i| select.wire(&format!("main.selected[{i}]")))
        .collect();
    let verdicts = [
        picus_verdicts::<IsEqual<32>>(
            &work,
            "equal",
            &[577],
            &equal,
            &[equal.wire("main.claimed")],
            Duration::from_secs(10),
        ),
        picus_verdicts::<Selected<32>>(
            &work,
            "select",
            &(578..610).collect::<Vec<_>>(),
            &select,
            &outputs,
            Duration::from_secs(10),
        ),
    ];
    eprintln!("Bytes assertion/select Picus {verdicts:?}; Unknown is partial coverage");
    for (sdk, reference) in verdicts {
        assert!(matches!(sdk, Verdict::Safe | Verdict::Unknown));
        assert!(matches!(reference, Verdict::Safe | Verdict::Unknown));
    }
}
