#![cfg(feature = "external-tools")]
use super::fixtures::HashBytes;
use crate::harness::{
    circomlib,
    equivalence::picus_verdicts,
    fixture::picus_export,
    picus::{picus_wire, promote_all, verdict_within, Verdict},
    WorkDir,
};
use std::time::Duration;
#[test]
fn picus_checks_a_checked_single_chunk_hash_with_a_bounded_timeout() {
    let work = WorkDir::new("bytes-hash-checked-packing-picus");
    let export = picus_export::<HashBytes<31>>();
    let output = picus_wire(&export, 280);
    let verdict = verdict_within(
        &work,
        "packed",
        &promote_all(&export, &[output]),
        Duration::from_secs(15),
    );
    eprintln!("checked single-chunk hash Picus {verdict:?}; Unknown is partial coverage");
    assert!(matches!(verdict, Verdict::Safe | Verdict::Unknown));
}
#[test]
fn picus_checks_two_chunk_hashes_with_a_bounded_timeout() {
    let work = WorkDir::new("bytes-hash-poseidon-picus");
    let circom = circomlib::compile("bytes/hash/hash32.circom");
    let verdicts = picus_verdicts::<HashBytes<32>>(
        &work,
        "hash",
        &[289],
        &circom,
        &[circom.wire("main.claimed")],
        Duration::from_secs(15),
    );
    eprintln!("hash_bytes Picus {verdicts:?}; Unknown is partial coverage");
    assert!(matches!(verdicts.0, Verdict::Safe | Verdict::Unknown));
    assert!(matches!(verdicts.1, Verdict::Safe | Verdict::Unknown));
}
