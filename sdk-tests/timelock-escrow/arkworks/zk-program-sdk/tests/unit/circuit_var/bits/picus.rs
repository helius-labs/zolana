#![cfg(feature = "external-tools")]

use std::time::Duration;

use super::fixtures::{CheckBits, FromBits, ToBits};
use crate::harness::{
    circomlib,
    equivalence::picus_verdicts,
    fixture::picus_export,
    iden3::{read_r1cs, R1csHeader},
    picus::{verdict_within, Verdict},
    WorkDir,
};

const LIMIT: Duration = Duration::from_secs(120);

#[test]
fn the_picus_export_makes_the_bit_witnesses_its_outputs() {
    let r1cs = read_r1cs(&picus_export::<CheckBits<4>>());
    assert_eq!(
        (r1cs.header, r1cs.wire_labels),
        (
            R1csHeader {
                public_outputs: 4,
                ..R1csHeader::bn254(6, 0, 1, 5)
            },
            vec![0, 2, 3, 4, 5, 1],
        )
    );
}

#[test]
fn picus_finds_check_bits_and_num2bits_deterministic() {
    let compiled = circomlib::compile("circuit_var/bits/check_bits.circom");
    let work = WorkDir::new("bits-picus-check");
    assert_eq!(
        picus_verdicts::<CheckBits<4>>(&work, "check-bits", &[], &compiled, &[], LIMIT),
        (Verdict::Safe, Verdict::Safe)
    );
}

#[test]
fn picus_finds_the_claimed_bits_fixed_by_x_in_both() {
    let compiled = circomlib::compile("circuit_var/bits/to_bits.circom");
    let work = WorkDir::new("bits-picus-to");
    let circom_bits: Vec<usize> = (0..4)
        .map(|bit| compiled.wire(&format!("main.bits[{bit}]")))
        .collect();
    assert_eq!(
        picus_verdicts::<ToBits<4>>(
            &work,
            "to-bits",
            &[2, 3, 4, 5],
            &compiled,
            &circom_bits,
            LIMIT
        ),
        (Verdict::Safe, Verdict::Safe)
    );
}

#[test]
fn picus_finds_the_value_fixed_by_its_bits_in_both() {
    let compiled = circomlib::compile("circuit_var/bits/from_bits.circom");
    let work = WorkDir::new("bits-picus-from");
    assert_eq!(
        picus_verdicts::<FromBits<4>>(
            &work,
            "from-bits",
            &[5],
            &compiled,
            &[compiled.wire("main.value")],
            LIMIT
        ),
        (Verdict::Safe, Verdict::Safe)
    );
}

#[test]
fn picus_finds_the_1_and_5_bit_decompositions_deterministic() {
    let work = WorkDir::new("bits-picus-widths");
    assert_eq!(
        (
            verdict_within(
                &work,
                "check-bits-1",
                &picus_export::<CheckBits<1>>(),
                LIMIT
            ),
            verdict_within(
                &work,
                "check-bits-5",
                &picus_export::<CheckBits<5>>(),
                LIMIT
            ),
        ),
        (Verdict::Safe, Verdict::Safe)
    );
}
