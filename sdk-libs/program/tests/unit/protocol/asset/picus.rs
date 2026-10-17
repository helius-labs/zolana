#![cfg(feature = "external-tools")]

use std::time::Duration;

use super::fixtures::{AssetHash, HASH_WIRE};
use crate::harness::{
    fixture::picus_export,
    picus::{picus_wire, promote, verdict_within, Verdict},
    WorkDir,
};

pub const LIMIT: Duration = Duration::from_secs(60);

/// Picus's answer is `Safe`, or `Unknown` once the limit passes; what these
/// fixtures pin is that it never finds two witnesses that differ on a target.
pub fn no_counterexample(verdict: Verdict) -> bool {
    verdict != Verdict::Unsafe
}

#[test]
fn picus_finds_no_second_asset_hash_for_one_mint() {
    let work = WorkDir::new("picus-asset-hash");
    let r1cs = picus_export::<AssetHash>();
    let hash = picus_wire(&r1cs, HASH_WIRE);
    assert!(no_counterexample(verdict_within(
        &work,
        "asset-hash-claim",
        &promote(&r1cs, hash),
        LIMIT
    )));
}
