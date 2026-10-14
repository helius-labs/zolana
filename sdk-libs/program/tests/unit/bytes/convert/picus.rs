#![cfg(feature = "external-tools")]

use super::{
    external::{pack_circom, split_circom},
    fixtures::{Allocated, Pack, Split},
};
use crate::harness::{
    equivalence::picus_verdicts,
    fixture::picus_export,
    iden3::read_r1cs,
    picus::{verdict_within, Verdict},
    WorkDir,
};
use std::time::Duration;
const LIMIT: Duration = Duration::from_secs(15);

#[test]
fn picus_checks_byte_allocation_with_a_bounded_timeout() {
    let work = WorkDir::new("picus-bytes-allocated");
    let r1cs = picus_export::<Allocated<2>>();
    assert_eq!(read_r1cs(&r1cs).header.public_outputs, 16);
    let verdict = verdict_within(&work, "allocated", &r1cs, LIMIT);
    eprintln!("Bytes allocation Picus {verdict:?}; Unknown is partial coverage");
    assert!(matches!(verdict, Verdict::Safe | Verdict::Unknown));
}

#[test]
fn picus_checks_split_determinism_with_a_bounded_timeout() {
    let work = WorkDir::new("picus-bytes-split");
    let circom = split_circom();
    let claims = [circom.wire("main.bytes[0]"), circom.wire("main.bytes[1]")];
    let verdicts = picus_verdicts::<Split<2, 0>>(&work, "split", &[2, 3], &circom, &claims, LIMIT);
    eprintln!("Bytes split Picus {verdicts:?}; Unknown is partial coverage");
    assert!(matches!(verdicts.0, Verdict::Safe | Verdict::Unknown));
    assert!(matches!(verdicts.1, Verdict::Safe | Verdict::Unknown));
}

#[test]
fn picus_checks_packing_determinism_with_a_bounded_timeout() {
    let work = WorkDir::new("picus-bytes-pack");
    let circom = pack_circom();
    let packed = circom.wire("main.packed");
    let verdicts = picus_verdicts::<Pack<2, 0>>(&work, "pack", &[19], &circom, &[packed], LIMIT);
    eprintln!("Bytes packing Picus {verdicts:?}; Unknown is partial coverage");
    assert!(matches!(verdicts.0, Verdict::Safe | Verdict::Unknown));
    assert!(matches!(verdicts.1, Verdict::Safe | Verdict::Unknown));
}
