#![cfg(feature = "external-tools")]
use super::{
    external::compiled,
    fixtures::{OneHot, SelectIndex},
};
use crate::harness::{equivalence::picus_verdicts, picus::Verdict, WorkDir};
use std::time::Duration;
#[test]
fn picus_proves_flags_and_selection_fixed_by_the_index_and_items() {
    let work = WorkDir::new("index-picus");
    let flags = compiled("one_hot");
    let reference_flags: Vec<_> = (0..3)
        .map(|index| flags.wire(&format!("main.flags[{index}]")))
        .collect();
    assert_eq!(
        picus_verdicts::<OneHot<3>>(
            &work,
            "one-hot",
            &[2, 3, 4],
            &flags,
            &reference_flags,
            Duration::from_secs(30)
        ),
        (Verdict::Safe, Verdict::Safe)
    );
    let select = compiled("select_index");
    assert_eq!(
        picus_verdicts::<SelectIndex<3>>(
            &work,
            "select-index",
            &[5],
            &select,
            &[select.wire("main.selected")],
            Duration::from_secs(30)
        ),
        (Verdict::Safe, Verdict::Safe)
    );
}
