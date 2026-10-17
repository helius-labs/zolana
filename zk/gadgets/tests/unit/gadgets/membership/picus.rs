#![cfg(feature = "external-tools")]
use super::{
    external::compiled,
    fixtures::{AssertIn, IsIn},
};
use crate::harness::{equivalence::picus_verdicts, picus::Verdict, WorkDir};
use std::time::Duration;
#[test]
fn picus_proves_membership_flags_deterministic_in_both_relations() {
    let work = WorkDir::new("membership-picus");
    let reference = compiled("membership");
    assert_eq!(
        picus_verdicts::<IsIn<3>>(
            &work,
            "is-in",
            &[5],
            &reference,
            &[reference.wire("main.member")],
            Duration::from_secs(30)
        ),
        (Verdict::Safe, Verdict::Safe)
    );
}
#[test]
fn picus_finds_multiple_members_can_satisfy_assert_in() {
    let work = WorkDir::new("assert-in-picus");
    let reference = compiled("assert_in");
    assert_eq!(
        picus_verdicts::<AssertIn<3>>(
            &work,
            "assert-in",
            &[1],
            &reference,
            &[reference.wire("main.value")],
            Duration::from_secs(30)
        ),
        (Verdict::Unsafe, Verdict::Unsafe)
    );
}
