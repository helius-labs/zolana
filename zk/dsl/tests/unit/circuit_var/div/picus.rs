#![cfg(feature = "external-tools")]

use std::time::Duration;

use super::fixtures::{Div, FourOver, INVERSE_WIRE, PRODUCT_WIRE, QUOTIENT_WIRE};
use crate::harness::{
    circom,
    equivalence::picus_verdicts,
    fixture::picus_export,
    iden3::{read_r1cs, R1csHeader},
    picus::{verdict_within, Verdict},
    WorkDir,
};

const LIMIT: Duration = Duration::from_secs(120);

#[test]
fn the_picus_export_makes_the_inverse_and_the_product_its_outputs() {
    let r1cs = read_r1cs(&picus_export::<Div>());
    assert_eq!(
        (r1cs.header, r1cs.wire_labels),
        (
            R1csHeader {
                public_outputs: 2,
                ..R1csHeader::bn254(6, 0, 3, 3)
            },
            vec![
                0,
                INVERSE_WIRE as u64,
                PRODUCT_WIRE as u64,
                1,
                2,
                QUOTIENT_WIRE as u64
            ],
        )
    );
}

#[test]
fn picus_finds_the_sdk_and_the_circom_quotient_deterministic() {
    let compiled = circom::compile("circuit_var/div/div.circom");
    let work = WorkDir::new("div-picus");
    assert_eq!(
        (
            picus_verdicts::<Div>(
                &work,
                "div",
                &[QUOTIENT_WIRE],
                &compiled,
                &[compiled.wire("main.quotient")],
                LIMIT,
            ),
            verdict_within(&work, "four-over", &picus_export::<FourOver>(), LIMIT),
        ),
        ((Verdict::Safe, Verdict::Safe), Verdict::Safe)
    );
}
