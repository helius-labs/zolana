#![cfg(feature = "external-tools")]

use ark_bn254::Fr;
use ark_ff::One;
use serde_json::json;
use zk_program_sdk::{Bytes, ZkCircuit};

use super::{
    fixtures::{pack_fixture, split_fixture, Allocated, Pack, Split},
    vectors::{Pair, Vector, TOO_LARGE, VALID, WRONG},
};
use crate::{
    bytes::support::{decimals, packed},
    harness::{
        circom::Compiled,
        circomlib,
        equivalence::{accepts, assert_relation_equivalent, sizes, Accepts, Case, SdkWitness},
        field::{decimal, field, MODULUS_MINUS_1},
        fixture::{assignment, with_wires, Size, Visited},
        iden3::write_wtns,
        snarkjs::{self, WtnsCheck},
        WorkDir,
    },
};

pub fn allocate_circom() -> Compiled {
    circomlib::compile("bytes/convert/allocate.circom")
}

pub fn split_circom() -> Compiled {
    circomlib::compile("bytes/convert/split.circom")
}

pub fn pack_circom() -> Compiled {
    circomlib::compile("bytes/convert/pack.circom")
}

fn of_width(vectors: &[Vector], width: usize) -> Vec<Vector> {
    vectors
        .iter()
        .filter(|vector| vector.width() == width)
        .copied()
        .collect()
}

fn split_inputs(pair: &Pair) -> Vec<(&'static str, Vec<String>)> {
    vec![
        ("value", vec![decimal(pair.value)]),
        ("bytes", decimals(&pair.bytes)),
    ]
}

fn pack_inputs(pair: &Pair) -> Vec<(&'static str, Vec<String>)> {
    vec![
        ("bytes", decimals(&pair.bytes)),
        ("packed", vec![decimal(pair.value)]),
    ]
}

fn split_cases() -> Vec<Case<Split<2, 0>>> {
    let valid = of_width(&VALID, 2).into_iter().map(|vector| Case {
        name: vector.name,
        holds: true,
        fixture: split_fixture(&vector.pair()),
        sdk_witness: SdkWitness::Assignment,
        circom: split_inputs(&vector.pair()),
    });
    let wrong = of_width(&WRONG, 2).into_iter().map(|vector| Case {
        name: vector.name,
        holds: false,
        fixture: split_fixture(&vector.pair()),
        sdk_witness: SdkWitness::Tampered {
            honest: split_fixture(&vector.split_pair()),
            wires: vector
                .bytes()
                .iter()
                .enumerate()
                .map(|(byte, value)| (2 + byte, Fr::from(u64::from(*value))))
                .collect(),
        },
        circom: split_inputs(&vector.pair()),
    });
    let too_large = of_width(&TOO_LARGE, 2).into_iter().map(|vector| Case {
        name: vector.name,
        holds: false,
        fixture: split_fixture(&vector.pair()),
        sdk_witness: SdkWitness::Tampered {
            honest: split_fixture(&vector.packed_pair()),
            wires: vec![(1, vector.value().into())],
        },
        circom: split_inputs(&vector.pair()),
    });
    valid.chain(wrong).chain(too_large).collect()
}

fn pack_cases() -> Vec<Case<Pack<2, 0>>> {
    let valid = of_width(&VALID, 2).into_iter().map(|vector| Case {
        name: vector.name,
        holds: true,
        fixture: pack_fixture(&vector.pair()),
        sdk_witness: SdkWitness::Assignment,
        circom: pack_inputs(&vector.pair()),
    });
    let wrong = [of_width(&WRONG, 2), of_width(&TOO_LARGE, 2)]
        .concat()
        .into_iter()
        .map(|vector| Case {
            name: vector.name,
            holds: false,
            fixture: pack_fixture(&vector.pair()),
            sdk_witness: SdkWitness::Tampered {
                honest: pack_fixture(&vector.packed_pair()),
                wires: vec![(19, vector.value().into())],
            },
            circom: pack_inputs(&vector.pair()),
        });
    valid.chain(wrong).collect()
}

#[test]
fn a_split_is_relation_equivalent_to_num2bits_and_big_endian_bytes() {
    assert_relation_equivalent(&split_circom(), &split_cases());
}

#[test]
fn a_pack_is_relation_equivalent_to_checked_bytes_and_a_big_endian_sum() {
    assert_relation_equivalent(&pack_circom(), &pack_cases());
}

#[test]
fn the_sdk_and_circom_sizes_are_pinned() {
    assert_eq!(
        (
            sizes::<Allocated<2>>(&allocate_circom()),
            sizes::<Split<2, 0>>(&split_circom()),
            sizes::<Pack<2, 0>>(&pack_circom()),
        ),
        (
            (
                Size {
                    constraints: 18,
                    variables: 19
                },
                Size {
                    constraints: 20,
                    variables: 21
                }
            ),
            (
                Size {
                    constraints: 19,
                    variables: 20
                },
                Size {
                    constraints: 20,
                    variables: 21
                }
            ),
            (
                Size {
                    constraints: 19,
                    variables: 20
                },
                Size {
                    constraints: 26,
                    variables: 27
                }
            ),
        )
    );
}

/// Two byte witnesses, one out of range. The native run cannot hold such a
/// byte, since a byte proof input is a `u8`: each case's fixture holds the
/// `honest` bytes, and the SDK witness overwrites both byte wires with
/// `witness`, leaving their bits those of `honest`.
struct OutOfRange {
    name: &'static str,
    honest: [u8; 2],
    witness: [Fr; 2],
}

impl OutOfRange {
    fn byte_wires(&self) -> Vec<(usize, Fr)> {
        vec![(1, self.witness[0]), (10, self.witness[1])]
    }

    fn circom_bytes(&self) -> Vec<String> {
        self.witness.map(|byte| decimal(byte.into())).to_vec()
    }

    fn packed(&self) -> Fr {
        self.witness[0] * Fr::from(256u64) + self.witness[1]
    }
}

fn out_of_range() -> Vec<OutOfRange> {
    let p_minus_1 = field(MODULUS_MINUS_1).into();
    vec![
        OutOfRange {
            name: "256 then 0",
            honest: [0, 0],
            witness: [Fr::from(256u64), Fr::from(0u64)],
        },
        OutOfRange {
            name: "0 then 511",
            honest: [0, 255],
            witness: [Fr::from(0u64), Fr::from(511u64)],
        },
        OutOfRange {
            name: "p - 1 then 0",
            honest: [0, 0],
            witness: [p_minus_1, Fr::from(0u64)],
        },
    ]
}

const REFUSED_BUT_NATIVE: Accepts = Accepts {
    sdk_native: true,
    sdk_r1cs: false,
    circom_witness: false,
    circom_r1cs: false,
};

#[test]
fn a_byte_of_256_or_more_is_refused_by_the_sdk_rows_and_by_circomlib_num2bits() {
    let allocated = |case: &OutOfRange| Allocated {
        bytes: Bytes(case.honest),
    };
    let allocate: Vec<Case<Allocated<2>>> = out_of_range()
        .iter()
        .map(|case| Case {
            name: case.name,
            holds: false,
            fixture: allocated(case),
            sdk_witness: SdkWitness::Tampered {
                honest: allocated(case),
                wires: case.byte_wires(),
            },
            circom: vec![("in", case.circom_bytes())],
        })
        .collect();
    let pack_of = |case: &OutOfRange| {
        pack_fixture::<2, 0>(&Pair {
            value: packed(&case.honest),
            bytes: case.honest.to_vec(),
        })
    };
    let pack: Vec<Case<Pack<2, 0>>> = out_of_range()
        .iter()
        .map(|case| Case {
            name: case.name,
            holds: false,
            fixture: pack_of(case),
            sdk_witness: SdkWitness::Tampered {
                honest: pack_of(case),
                wires: [case.byte_wires(), vec![(19, case.packed())]].concat(),
            },
            circom: vec![
                ("bytes", case.circom_bytes()),
                ("packed", vec![decimal(case.packed().into())]),
            ],
        })
        .collect();
    let names: Vec<&'static str> = out_of_range().iter().map(|case| case.name).collect();
    let refused: Visited<Accepts> = names
        .iter()
        .map(|name| (*name, REFUSED_BUT_NATIVE))
        .collect();
    assert_eq!(
        (
            accepts(&allocate_circom(), &allocate),
            accepts(&pack_circom(), &pack)
        ),
        (refused.clone(), refused)
    );
}

fn wtns_checks<F: ZkCircuit>(
    work: &WorkDir,
    name: &str,
    fixture: &F,
    tampered: &[(usize, Fr)],
) -> (WtnsCheck, WtnsCheck) {
    let r1cs = work.write(&format!("{name}.r1cs"), &F::export_r1cs().expect("r1cs"));
    let honest = assignment(fixture);
    let honest_path = work.write(&format!("{name}.wtns"), &write_wtns(&honest));
    let tampered_path = work.write(
        &format!("{name}-tampered.wtns"),
        &write_wtns(&with_wires(honest, tampered)),
    );
    (
        snarkjs::wtns_check(&r1cs, &honest_path),
        snarkjs::wtns_check(&r1cs, &tampered_path),
    )
}

#[test]
fn snarkjs_accepts_every_honest_conversion_and_rejects_a_tampered_one() {
    let work = WorkDir::new("bytes-convert-wtns");
    let pair = VALID[6].pair();
    assert_eq!(
        [
            wtns_checks(
                &work,
                "allocated",
                &Allocated::<2> {
                    bytes: Bytes([1, 2])
                },
                &[(1, Fr::from(256u64))]
            ),
            wtns_checks(
                &work,
                "split",
                &split_fixture::<2, 0>(&pair),
                &[(2, Fr::from(2u64)), (3, Fr::one())]
            ),
            wtns_checks(
                &work,
                "pack",
                &pack_fixture::<2, 0>(&pair),
                &[(19, Fr::from(513u64))]
            ),
        ],
        [0; 3].map(|_| (WtnsCheck::Accepted, WtnsCheck::Rejected))
    );
}

#[test]
fn snarkjs_proves_and_verifies_a_31_byte_pack() {
    let work = WorkDir::new("bytes-pack-groth16");
    let fixture = pack_fixture::<31, 0>(&VALID[9].pair());
    let r1cs = work.write("pack.r1cs", &Pack::<31, 0>::export_r1cs().expect("r1cs"));
    let wtns = work.write(
        "pack.wtns",
        &fixture.export_assignment().expect("assignment"),
    );
    assert_eq!(snarkjs::groth16(&work, &r1cs, &wtns), (true, json!([])));
}
