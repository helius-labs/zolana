#![cfg(feature = "external-tools")]

use std::time::Duration;

use super::fixtures::{Asserted, Refresh};
use crate::harness::{
    fixture::picus_export,
    picus::{verdict_within, Verdict},
    WorkDir,
};

const LIMIT: Duration = Duration::from_secs(30);

#[test]
fn picus_finds_no_counterexample_for_a_whole_refresh_within_its_limit() {
    let work = WorkDir::new("picus-transaction-refresh");
    let verdict = verdict_within(
        &work,
        "refresh",
        &picus_export::<Asserted<Refresh>>(),
        LIMIT,
    );
    assert_ne!(verdict, Verdict::Unsafe);
}
