#![cfg(feature = "external-tools")]

use std::time::Duration;

use super::fixtures::{Pow, Pow5, FIRST_WITNESS_WIRE, POWER_WIRE};
use crate::harness::{
    circom,
    equivalence::picus_verdicts,
    fixture::{export, picus_export},
    iden3::{read_r1cs, R1csHeader},
    picus::{promote, verdict_within, Verdict},
    WorkDir,
};

const LIMIT: Duration = Duration::from_secs(120);

fn verdict(work: &WorkDir, name: &str, r1cs: &[u8]) -> Verdict {
    verdict_within(work, name, r1cs, LIMIT)
}

#[test]
fn the_picus_export_makes_the_three_witnesses_its_outputs() {
    let r1cs = read_r1cs(&picus_export::<Pow5>());
    let witnesses = (FIRST_WITNESS_WIRE..FIRST_WITNESS_WIRE + 3).map(|wire| wire as u64);
    assert_eq!(
        (
            r1cs.header,
            r1cs.wire_labels,
            picus_export::<Pow<0>>(),
            picus_export::<Pow<1>>(),
        ),
        (
            R1csHeader {
                public_outputs: 3,
                ..R1csHeader::bn254(6, 0, 2, 4)
            },
            [vec![0], witnesses.collect(), vec![1, POWER_WIRE as u64]].concat(),
            export::<Pow<0>>(),
            export::<Pow<1>>(),
        )
    );
}

#[test]
fn picus_finds_the_sdk_and_the_circom_power_deterministic() {
    let compiled = circom::compile("circuit_var/pow/pow.circom");
    let work = WorkDir::new("pow-picus");
    assert_eq!(
        picus_verdicts::<Pow5>(
            &work,
            "pow5",
            &[POWER_WIRE],
            &compiled,
            &[compiled.wire("main.power")],
            LIMIT,
        ),
        (Verdict::Safe, Verdict::Safe)
    );
}

#[test]
fn picus_finds_x_free_in_x_to_the_0_and_fixed_by_the_power_in_x_to_the_1() {
    let work = WorkDir::new("pow-picus-edges");
    assert_eq!(
        (
            verdict(&work, "pow0-x", &promote(&picus_export::<Pow<0>>(), 1)),
            verdict(
                &work,
                "pow0-power",
                &promote(&picus_export::<Pow<0>>(), POWER_WIRE)
            ),
            verdict(&work, "pow1-x", &promote(&picus_export::<Pow<1>>(), 1)),
        ),
        (Verdict::Unsafe, Verdict::Safe, Verdict::Safe)
    );
}
