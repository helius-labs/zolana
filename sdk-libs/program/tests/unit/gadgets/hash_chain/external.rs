#![cfg(feature = "external-tools")]

use ark_bn254::Fr;
use ark_ff::One;
use serde_json::json;
use zolana_program::{circuit::Field, ZkCircuit};

use super::{
    fixtures::{fixture, reference_chain, Chain},
    r1cs::{chain_wire, pinned},
    vectors::{Vector, INVALID, VALID},
};
use crate::{
    gadgets::relation::assert_relation_equivalent,
    harness::{
        circom::Compiled,
        circomlib,
        equivalence::{sizes, Case, SdkWitness},
        field::decimal,
        fixture::{assignment, with_wires, Size},
        iden3::write_wtns,
        snarkjs::{self, WtnsCheck},
        WorkDir,
    },
};

const LEN: usize = 3;

pub fn compiled(len: usize) -> Compiled {
    circomlib::compile(&format!("gadgets/hash_chain/hash_chain_{len}.circom"))
}

fn padded(vector: &Vector) -> Vec<Field> {
    let mut values = vector.values();
    values.resize(LEN, Field::from(0u64));
    values
}

fn circom_inputs(values: &[Field], chain: Field) -> Vec<(&'static str, Vec<String>)> {
    vec![
        (
            "values",
            values.iter().map(|value| decimal(*value)).collect(),
        ),
        ("chain", vec![decimal(chain)]),
    ]
}

/// Every vector of at most three values, padded with zeros to three: a
/// trailing zero leaves the chain unchanged.
fn cases() -> Vec<Case<Chain<LEN>>> {
    let short = |vectors: &'static [Vector]| vectors.iter().filter(|vector| vector.len() <= LEN);
    let valid = short(&VALID).flat_map(|vector| {
        let values = padded(vector);
        let wrong = vector.chain() + Field::from(1u64);
        [
            Case {
                name: vector.name,
                holds: true,
                fixture: fixture::<LEN>(&values, vector.chain()),
                sdk_witness: SdkWitness::Assignment,
                circom: circom_inputs(&values, vector.chain()),
            },
            Case {
                name: "the chain plus one",
                holds: false,
                fixture: fixture::<LEN>(&values, wrong),
                sdk_witness: SdkWitness::Tampered {
                    honest: fixture::<LEN>(&values, vector.chain()),
                    wires: vec![(chain_wire(LEN), wrong.into())],
                },
                circom: circom_inputs(&values, wrong),
            },
        ]
    });
    let invalid = short(&INVALID).map(|vector| {
        let values = padded(vector);
        Case {
            name: vector.name,
            holds: false,
            fixture: fixture::<LEN>(&values, vector.chain()),
            sdk_witness: SdkWitness::Tampered {
                honest: fixture::<LEN>(&values, reference_chain(&values)),
                wires: vec![(chain_wire(LEN), vector.chain().into())],
            },
            circom: circom_inputs(&values, vector.chain()),
        }
    });
    valid.chain(invalid).collect()
}

#[test]
fn the_circom_chain_over_circomlib_accepts_exactly_the_sdks_claims() {
    assert_relation_equivalent(&compiled(LEN), &cases());
}

#[test]
fn the_sizes_are_pinned_against_the_circom_chain() {
    assert_eq!(
        sizes::<Chain<LEN>>(&compiled(LEN)),
        (
            pinned(LEN),
            Size {
                constraints: 2330,
                variables: 2334,
            }
        )
    );
}

#[test]
fn snarkjs_accepts_the_sdk_pair_and_rejects_a_tampered_chain() {
    let work = WorkDir::new("gadgets-hash-chain-snarkjs");
    let vector = VALID
        .iter()
        .find(|vector| vector.values == ["1", "2", "3"])
        .expect("the [1, 2, 3] vector");
    let honest = fixture::<LEN>(&vector.values(), vector.chain());
    let r1cs = work.write(
        "chain.r1cs",
        &Chain::<LEN>::export_r1cs().expect("r1cs export"),
    );
    let witness = assignment(&honest);
    let wire = chain_wire(LEN);
    let chained = *witness.get(wire).expect("the chain");
    let tampered = with_wires(witness.clone(), &[(wire, chained + Fr::one())]);
    let honest = work.write(
        "honest.wtns",
        &honest.export_assignment().expect("assignment"),
    );
    let tampered = work.write("tampered.wtns", &write_wtns(&tampered));
    assert_eq!(
        (
            snarkjs::wtns_check(&r1cs, &honest),
            snarkjs::wtns_check(&r1cs, &tampered),
        ),
        (WtnsCheck::Accepted, WtnsCheck::Rejected)
    );
}

#[test]
fn snarkjs_proves_and_verifies_a_chain_that_skips_a_zero() {
    let work = WorkDir::new("gadgets-hash-chain-groth16");
    let vector = VALID
        .iter()
        .find(|vector| vector.values == ["5", "0", "7"])
        .expect("the [5, 0, 7] vector");
    let fixture = fixture::<LEN>(&vector.values(), vector.chain());
    let r1cs = work.write(
        "chain.r1cs",
        &Chain::<LEN>::export_r1cs().expect("r1cs export"),
    );
    let wtns = work.write(
        "chain.wtns",
        &fixture.export_assignment().expect("assignment"),
    );
    assert_eq!(snarkjs::groth16(&work, &r1cs, &wtns), (true, json!([])));
}
