#![cfg(feature = "external-tools")]
use super::{fixtures::HashBytes, vectors::native_hash};
use crate::{
    bytes::support::decimals,
    harness::{
        circomlib,
        equivalence::{assert_relation_equivalent, sizes, Case, SdkWitness},
        field::decimal,
        fixture::{assignment, with_wires},
        iden3::write_wtns,
        snarkjs::{self, WtnsCheck},
        WorkDir,
    },
};
use ark_bn254::Fr;
use serde_json::json;
use zolana_program::{Bytes, ZkCircuit};

fn equivalent<const N: usize>(source: &str, counts: (usize, usize, usize, usize)) {
    let compiled = circomlib::compile(source);
    let mut cases = Vec::new();
    for bytes in [[0; N], [255; N], std::array::from_fn(|i| i as u8)] {
        let honest = HashBytes {
            bytes: Bytes(bytes),
            hash: native_hash(&bytes),
        };
        for correct in [true, false] {
            let claimed = if correct {
                honest.hash
            } else {
                (Fr::from(honest.hash) + Fr::from(1u64)).into()
            };
            cases.push(Case {
                name: if correct { "honest hash" } else { "wrong hash" },
                holds: correct,
                fixture: HashBytes {
                    hash: claimed,
                    ..honest
                },
                sdk_witness: SdkWitness::Tampered {
                    honest,
                    wires: vec![(9 * N + 1, claimed.into())],
                },
                circom: vec![
                    ("bytes", decimals(&bytes)),
                    ("claimed", vec![decimal(claimed)]),
                ],
            });
        }
    }
    assert_relation_equivalent(&compiled, &cases);
    let (sdk, reference) = sizes::<HashBytes<N>>(&compiled);
    assert_eq!(
        (
            sdk.constraints,
            sdk.variables,
            reference.constraints,
            reference.variables
        ),
        counts
    );
}
#[test]
fn hash_bytes_matches_circomlib_poseidon_at_two_and_three_chunks() {
    equivalent::<32>("bytes/hash/hash32.circom", (529, 530, 1189, 1190));
    equivalent::<63>("bytes/hash/hash63.circom", (1048, 1049, 2361, 2362));
}

#[test]
fn snarkjs_checks_tampering_and_proves_a_two_chunk_hash() {
    let work = WorkDir::new("bytes-hash-snarkjs");
    let bytes = std::array::from_fn(|i| i as u8);
    let fixture = HashBytes::<32> {
        bytes: Bytes(bytes),
        hash: native_hash(&bytes),
    };
    let r1cs = work.write("hash.r1cs", &HashBytes::<32>::export_r1cs().expect("r1cs"));
    let witness = assignment(&fixture);
    let honest = work.write("honest.wtns", &write_wtns(&witness));
    let wrong = work.write(
        "wrong.wtns",
        &write_wtns(&with_wires(
            witness,
            &[(289, Fr::from(fixture.hash) + Fr::from(1u64))],
        )),
    );
    assert_eq!(
        (
            snarkjs::wtns_check(&r1cs, &honest),
            snarkjs::wtns_check(&r1cs, &wrong)
        ),
        (WtnsCheck::Accepted, WtnsCheck::Rejected)
    );
    assert_eq!(snarkjs::groth16(&work, &r1cs, &honest), (true, json!([])));
}
