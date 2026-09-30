#![cfg(feature = "external-tools")]

use ark_bn254::Fr;
use ark_ff::One;
use serde_json::json;
use zolana_program::{circuit::Field, ZkCircuit};

use super::{
    fixtures::{low_bits, CheckBits, CheckIsBool, FromBits, ToBits},
    vectors::{BitsVector, Vector, BITS_4, BOOL, TWO_POW_253_MINUS_1, WIDTH_4},
};
use crate::harness::{
    circom::{self, Asserts, Compiled},
    circomlib,
    equivalence::{assert_relation_equivalent, sizes, Case, SdkWitness},
    field::{decimal, field},
    fixture::{assignment, export, with_wires, Size},
    iden3::{read_r1cs, read_wtns, write_wtns},
    normalize::{constraints, Constraint},
    snarkjs::{self, WtnsCheck},
    WorkDir,
};

fn decimals(fields: &[Field]) -> Vec<String> {
    fields.iter().map(|field| decimal(*field)).collect()
}

fn check_bits_case(vector: &Vector) -> Case<CheckBits<4>> {
    let x = vector.field();
    Case {
        name: vector.name,
        holds: vector.holds,
        fixture: CheckBits { x },
        sdk_witness: if vector.holds {
            SdkWitness::Assignment
        } else {
            SdkWitness::Tampered {
                honest: CheckBits {
                    x: Field::from(0u64),
                },
                wires: vec![(1, x.into())],
            }
        },
        circom: vec![("x", vec![decimal(x)])],
    }
}

fn to_bits_case(vector: &BitsVector) -> Case<ToBits<4>> {
    let (x, bits) = (vector.value(), vector.bits());
    let fitting = if vector.value < 16 { vector.value } else { 0 };
    let claimed = (2..).zip(bits.map(Fr::from));
    Case {
        name: vector.name,
        holds: vector.holds,
        fixture: ToBits { x, bits },
        sdk_witness: if vector.holds {
            SdkWitness::Assignment
        } else {
            SdkWitness::Tampered {
                honest: ToBits {
                    x: Field::from(fitting),
                    bits: low_bits(fitting),
                },
                wires: [(1, x.into())].into_iter().chain(claimed).collect(),
            }
        },
        circom: vec![("x", vec![decimal(x)]), ("bits", decimals(&bits))],
    }
}

fn from_bits_case(vector: &BitsVector) -> Case<FromBits<4>> {
    let (bits, value) = (vector.bits(), vector.value());
    Case {
        name: vector.name,
        holds: vector.holds,
        fixture: FromBits { bits, value },
        sdk_witness: SdkWitness::Explicit(
            [Field::from(1u64)]
                .into_iter()
                .chain(bits)
                .chain([value])
                .map(Fr::from)
                .collect(),
        ),
        circom: vec![("bits", decimals(&bits)), ("value", vec![decimal(value)])],
    }
}

fn is_bool_case(vector: &Vector) -> Case<CheckIsBool> {
    let x = vector.field();
    Case {
        name: vector.name,
        holds: vector.holds,
        fixture: CheckIsBool { x },
        sdk_witness: SdkWitness::Explicit(vec![Fr::one(), x.into()]),
        circom: vec![("x", vec![decimal(x)])],
    }
}

fn is_bool() -> Compiled {
    circom::compile("circuit_var/bits/is_bool.circom")
}

#[test]
fn check_bits_accepts_exactly_the_values_circomlib_num2bits_accepts() {
    let compiled = circomlib::compile("circuit_var/bits/check_bits.circom");
    assert_relation_equivalent(&compiled, &WIDTH_4.map(|vector| check_bits_case(&vector)));
    assert_eq!(
        sizes::<CheckBits<4>>(&compiled),
        (
            Size {
                constraints: 5,
                variables: 6
            },
            Size {
                constraints: 10,
                variables: 11
            }
        )
    );
}

#[test]
fn to_bits_le_accepts_exactly_the_claims_circomlib_num2bits_accepts() {
    let compiled = circomlib::compile("circuit_var/bits/to_bits.circom");
    assert_relation_equivalent(&compiled, &BITS_4.map(|vector| to_bits_case(&vector)));
    assert_eq!(
        sizes::<ToBits<4>>(&compiled),
        (
            Size {
                constraints: 9,
                variables: 10
            },
            Size {
                constraints: 10,
                variables: 11
            }
        )
    );
}

#[test]
fn from_bits_le_accepts_exactly_the_claims_circomlib_bits2num_with_booleanity_accepts() {
    let compiled = circomlib::compile("circuit_var/bits/from_bits.circom");
    assert_relation_equivalent(&compiled, &BITS_4.map(|vector| from_bits_case(&vector)));
    assert_eq!(
        sizes::<FromBits<4>>(&compiled),
        (
            Size {
                constraints: 5,
                variables: 6
            },
            Size {
                constraints: 10,
                variables: 11
            }
        )
    );
}

#[test]
fn check_is_bool_is_row_for_row_the_circom_booleanity_constraint() {
    let compiled = is_bool();
    let (sdk, circom) = (read_r1cs(&export::<CheckIsBool>()), compiled.read_r1cs());
    let one = Fr::one();
    let row = vec![Constraint::Quadratic {
        a: vec![(0, one), (1, -one)],
        b: vec![(1, one)],
        c: vec![],
    }];
    let honest = || BOOL.into_iter().filter(|vector| vector.holds);
    assert_relation_equivalent(&compiled, &BOOL.map(|vector| is_bool_case(&vector)));
    assert_eq!(
        (
            &sdk.header,
            &sdk.wire_labels,
            constraints(&sdk),
            constraints(&circom),
            honest()
                .map(|vector| compiled.calculate(&is_bool_case(&vector).circom, Asserts::Abort))
                .collect::<Vec<_>>(),
        ),
        (
            &circom.header,
            &circom.wire_labels,
            row.clone(),
            row,
            honest()
                .map(|vector| Ok(assignment(&CheckIsBool { x: vector.field() })))
                .collect::<Vec<_>>(),
        )
    );
}

#[test]
fn snarkjs_accepts_the_check_bits_pair_and_rejects_each_flipped_bit() {
    let work = WorkDir::new("bits-snarkjs-sdk-pair");
    let r1cs = work.write("sdk.r1cs", &export::<CheckBits<4>>());
    let fitting: Vec<_> = WIDTH_4.into_iter().filter(|vector| vector.holds).collect();
    let checked: Vec<_> = fitting
        .iter()
        .enumerate()
        .map(|(index, vector)| {
            let honest = assignment(&CheckBits::<4> { x: vector.field() });
            let check = |label: String, witness: &[Fr]| {
                let wtns = work.write(&format!("{label}-{index}.wtns"), &write_wtns(witness));
                snarkjs::wtns_check(&r1cs, &wtns)
            };
            let flipped: Vec<_> = (2..6)
                .map(|wire| {
                    let witness = with_wires(honest.clone(), &[(wire, Fr::one() - honest[wire])]);
                    check(format!("bit-{wire}"), &witness)
                })
                .collect();
            (vector.name, check("honest".to_string(), &honest), flipped)
        })
        .collect();
    assert_eq!(
        checked,
        fitting
            .iter()
            .map(|vector| (
                vector.name,
                WtnsCheck::Accepted,
                vec![WtnsCheck::Rejected; 4]
            ))
            .collect::<Vec<_>>()
    );
}

#[test]
fn snarkjs_proves_and_verifies_a_253_bit_range_check() {
    let work = WorkDir::new("bits-snarkjs-groth16");
    let r1cs = work.write("sdk.r1cs", &export::<CheckBits<253>>());
    let wtns = work.write(
        "sdk.wtns",
        &CheckBits::<253> {
            x: field(TWO_POW_253_MINUS_1),
        }
        .export_assignment()
        .expect("assignment"),
    );
    assert_eq!(
        (
            read_wtns(&std::fs::read(&wtns).expect("wtns")).len(),
            snarkjs::groth16(&work, &r1cs, &wtns)
        ),
        (255, (true, json!([])))
    );
}
