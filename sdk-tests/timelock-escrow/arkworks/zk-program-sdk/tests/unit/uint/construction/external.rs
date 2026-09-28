#![cfg(feature = "external-tools")]

use ark_bn254::Fr;
use ark_ff::One;
use serde_json::json;
use zk_program_sdk::ZkCircuit;

use super::{
    fixtures::{Borrowed, X_WIRE},
    vectors::{invalid, valid, Vector},
};
use crate::{
    harness::{
        circom::Compiled,
        circomlib,
        equivalence::{assert_relation_equivalent, sizes, Case, SdkWitness},
        field::decimal,
        fixture::{assignment, export, with_wires, Size},
        iden3::write_wtns,
        snarkjs::{self, WtnsCheck},
        WorkDir,
    },
    uint::{
        at_widths,
        rows::{field, low_bits},
        Widths,
    },
};

pub fn num2bits(bits: u32) -> Compiled {
    circomlib::compile(&format!("uint/construction/num2bits_{bits}.circom"))
}

fn case<const BITS: u32>(Vector { name, x }: Vector, holds: bool) -> Case<Borrowed<BITS>> {
    Case {
        name,
        holds,
        fixture: Borrowed::<BITS> { x: field(x) },
        sdk_witness: if holds {
            SdkWitness::Assignment
        } else {
            SdkWitness::Explicit([vec![Fr::one(), x], low_bits(x, BITS as usize)].concat())
        },
        circom: vec![("in", vec![decimal(field(x))])],
    }
}

struct Equivalent;

impl Widths for Equivalent {
    type Output = (Size, Size);

    fn at<const BITS: u32>(&self) -> (Size, Size) {
        let compiled = num2bits(BITS);
        let cases: Vec<_> = valid(BITS)
            .into_iter()
            .map(|vector| case::<BITS>(vector, true))
            .chain(
                invalid(BITS)
                    .into_iter()
                    .map(|vector| case::<BITS>(vector, false)),
            )
            .collect();
        assert_relation_equivalent(&compiled, &cases);
        sizes::<Borrowed<BITS>>(&compiled)
    }
}

#[test]
fn try_from_is_relation_equivalent_to_circomlib_num2bits_with_equal_sizes() {
    let size = |bits: usize| Size {
        constraints: bits + 1,
        variables: bits + 2,
    };
    assert_eq!(
        at_widths!(&Equivalent, [4, 64, 252]),
        [4, 64, 252]
            .map(|bits| (bits, (size(bits as usize), size(bits as usize))))
            .to_vec()
    );
}

struct Snarkjs;

impl Widths for Snarkjs {
    type Output = Vec<(&'static str, WtnsCheck, WtnsCheck)>;

    fn at<const BITS: u32>(&self) -> Self::Output {
        let work = WorkDir::new(&format!("uint-construction-wtns-{BITS}"));
        let r1cs = work.write("sdk.r1cs", &export::<Borrowed<BITS>>());
        valid(BITS)
            .into_iter()
            .enumerate()
            .map(|(index, Vector { name, x })| {
                let honest = assignment(&Borrowed::<BITS> { x: field(x) });
                let tampered = with_wires(honest.clone(), &[(X_WIRE, x + Fr::one())]);
                let honest = work.write(&format!("honest-{index}.wtns"), &write_wtns(&honest));
                let tampered =
                    work.write(&format!("tampered-{index}.wtns"), &write_wtns(&tampered));
                (
                    name,
                    snarkjs::wtns_check(&r1cs, &honest),
                    snarkjs::wtns_check(&r1cs, &tampered),
                )
            })
            .collect()
    }
}

#[test]
fn snarkjs_accepts_every_sdk_pair_and_rejects_a_tampered_value() {
    assert_eq!(
        at_widths!(&Snarkjs, [4, 64, 252]),
        [4, 64, 252]
            .map(|bits| {
                let checks = valid(bits)
                    .into_iter()
                    .map(|vector| (vector.name, WtnsCheck::Accepted, WtnsCheck::Rejected))
                    .collect();
                (bits, checks)
            })
            .to_vec()
    );
}

#[test]
fn snarkjs_proves_and_verifies_the_64_bit_range_check() {
    let work = WorkDir::new("uint-construction-groth16");
    let r1cs = work.write("sdk.r1cs", &export::<Borrowed<64>>());
    let fixture = Borrowed::<64> {
        x: field(Fr::from(u64::MAX)),
    };
    let wtns = work.write(
        "sdk.wtns",
        &fixture.export_assignment().expect("assignment"),
    );
    assert_eq!(snarkjs::groth16(&work, &r1cs, &wtns), (true, json!([])));
}
