#![cfg(feature = "external-tools")]

use std::time::Duration;

use super::{external::num2bits, fixtures::Borrowed};
use crate::{
    harness::{
        fixture::picus_export,
        picus::{circom_verdict, verdict_within, Verdict},
        WorkDir,
    },
    uint::{at_widths, picus_form::verdict_in_circom_form, Widths},
};

const LIMIT: Duration = Duration::from_secs(20);
const RAW_LIMIT: Duration = Duration::from_secs(10);

struct Deterministic<'a>(&'a WorkDir);

impl Widths for Deterministic<'_> {
    type Output = (Verdict, Verdict);

    fn at<const BITS: u32>(&self) -> (Verdict, Verdict) {
        let name = format!("range-check-{BITS}");
        (
            verdict_in_circom_form(self.0, &name, &picus_export::<Borrowed<BITS>>(), LIMIT),
            circom_verdict(self.0, &format!("{name}-num2bits"), &num2bits(BITS), LIMIT),
        )
    }
}

#[test]
fn picus_checks_normalized_range_checks_with_a_bounded_solver_budget() {
    let work = WorkDir::new("uint-construction-picus");
    for (bits, (sdk, reference)) in at_widths!(&Deterministic(&work), [4, 64, 252]) {
        eprintln!("Uint normalized construction Picus {bits}: SDK={sdk:?}, circom={reference:?}");
        assert_ne!(sdk, Verdict::Unsafe, "SDK width {bits}");
        assert_ne!(reference, Verdict::Unsafe, "Num2Bits width {bits}");
    }
}

#[test]
fn picus_checks_raw_exports_with_a_bounded_solver_budget() {
    let work = WorkDir::new("uint-construction-picus-raw");
    for (name, bytes) in [
        ("raw-4", picus_export::<Borrowed<4>>()),
        ("raw-64", picus_export::<Borrowed<64>>()),
    ] {
        let verdict = verdict_within(&work, name, &bytes, RAW_LIMIT);
        eprintln!("Uint construction Picus {name}: {verdict:?}");
        assert_ne!(verdict, Verdict::Unsafe);
    }
}
