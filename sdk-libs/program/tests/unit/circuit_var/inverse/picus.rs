#![cfg(feature = "external-tools")]

use std::time::Duration;

use super::fixtures::{Inverse, Unasserted, CLAIMED_WIRE, INVERSE_WIRE};
use crate::harness::{
    circom,
    equivalence::picus_verdicts,
    fixture::picus_export,
    iden3::{read_r1cs, R1csHeader},
    picus::{picus_wire, promote, verdict_within, Verdict},
    WorkDir,
};

const LIMIT: Duration = Duration::from_secs(120);

fn verdict(work: &WorkDir, name: &str, r1cs: &[u8]) -> Verdict {
    verdict_within(work, name, r1cs, LIMIT)
}

#[test]
fn the_picus_export_makes_the_inverse_witness_its_only_output() {
    let (inverse, unasserted) = (
        read_r1cs(&picus_export::<Inverse>()),
        read_r1cs(&picus_export::<Unasserted>()),
    );
    assert_eq!(
        (
            inverse.header,
            inverse.wire_labels,
            unasserted.header,
            unasserted.wire_labels
        ),
        (
            R1csHeader {
                public_outputs: 1,
                ..R1csHeader::bn254(4, 0, 2, 2)
            },
            vec![0, INVERSE_WIRE as u64, 1, CLAIMED_WIRE as u64],
            R1csHeader {
                public_outputs: 1,
                ..R1csHeader::bn254(3, 0, 1, 1)
            },
            vec![0, 2, 1],
        )
    );
}

#[test]
fn picus_finds_the_sdk_and_the_circom_inverse_deterministic() {
    let compiled = circom::compile("circuit_var/inverse/inverse.circom");
    let work = WorkDir::new("inverse-picus");
    assert_eq!(
        picus_verdicts::<Inverse>(
            &work,
            "inverse",
            &[CLAIMED_WIRE],
            &compiled,
            &[compiled.wire("main.inverse")],
            LIMIT,
        ),
        (Verdict::Safe, Verdict::Safe)
    );
}

#[test]
fn picus_finds_the_inverse_witness_fixed_by_x_and_x_fixed_by_the_claim() {
    let work = WorkDir::new("inverse-picus-witness");
    let r1cs = picus_export::<Inverse>();
    assert_eq!(
        (
            verdict(&work, "unasserted", &picus_export::<Unasserted>()),
            verdict(&work, "witness", &r1cs),
            verdict(&work, "x", &promote(&r1cs, picus_wire(&r1cs, 1))),
        ),
        (Verdict::Safe, Verdict::Safe, Verdict::Safe)
    );
}
