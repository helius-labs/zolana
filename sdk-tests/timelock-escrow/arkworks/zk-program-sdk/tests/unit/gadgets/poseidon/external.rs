#![cfg(feature = "external-tools")]

use ark_bn254::Fr;
use ark_ff::One;
use serde_json::json;
use zk_program_sdk::circuit::Field;

use super::{
    fixtures::{claim, every_arity, fixture, PerArity, PoseidonClaim},
    r1cs::{hash_wire, sbox_rows},
    vectors::{by_arity, Vector, INVALID, VALID},
};
use crate::{
    gadgets::{
        reference,
        relation::{accepts_in_parallel, expected},
    },
    harness::{
        circom::{Asserts, Compiled},
        circomlib,
        equivalence::{sizes, Accepts, Case, SdkWitness},
        fixture::{exported, per_vector, with_wires, Assignment, Export, Size, Visited},
        iden3::{write_wtns, R1cs},
        normalize::{constraints, Constraint},
        snarkjs::{self, WtnsCheck},
        WorkDir,
    },
};

/// circomlib's `Poseidon(n)` compiled with `--O0`: its S-boxes are the
/// SDK's plus the capacity element's first one, and it keeps every linear
/// signal assignment of its sparse mix layers as a row.
const CIRCOM_SIZES: [Size; 12] = [
    Size {
        constraints: 581,
        variables: 583,
    },
    Size {
        constraints: 768,
        variables: 771,
    },
    Size {
        constraints: 935,
        variables: 939,
    },
    Size {
        constraints: 1168,
        variables: 1173,
    },
    Size {
        constraints: 1353,
        variables: 1359,
    },
    Size {
        constraints: 1592,
        variables: 1599,
    },
    Size {
        constraints: 1803,
        variables: 1811,
    },
    Size {
        constraints: 1974,
        variables: 1983,
    },
    Size {
        constraints: 2093,
        variables: 2103,
    },
    Size {
        constraints: 2434,
        variables: 2445,
    },
    Size {
        constraints: 2463,
        variables: 2475,
    },
    Size {
        constraints: 2798,
        variables: 2811,
    },
];

pub fn compiled(arity: usize) -> Compiled {
    circomlib::compile(&format!("gadgets/poseidon/poseidon_{arity}.circom"))
}

fn quadratic(r1cs: &R1cs) -> usize {
    constraints(r1cs)
        .iter()
        .filter(|constraint| matches!(constraint, Constraint::Quadratic { .. }))
        .count()
}

fn of_arity(vectors: &[Vector], arity: usize) -> impl Iterator<Item = &Vector> {
    vectors.iter().filter(move |vector| vector.arity() == arity)
}

fn cases<const N: usize>() -> Vec<Case<PoseidonClaim<N>>> {
    let tampered = |vector: &Vector, claimed: Field| SdkWitness::Tampered {
        honest: fixture::<N>(&vector.inputs(), vector.hash()),
        wires: vec![(hash_wire(N), claimed.into())],
    };
    let honest = of_arity(&VALID, N).map(|vector| Case {
        name: vector.name,
        holds: true,
        fixture: fixture::<N>(&vector.inputs(), vector.hash()),
        sdk_witness: SdkWitness::Assignment,
        circom: vector.circom(vector.hash()),
    });
    let counting = by_arity(N);
    let wrong = counting.hash() + Field::from(1u64);
    let off_by_one = Case {
        name: "Poseidon(1, ..., n) claimed plus one",
        holds: false,
        fixture: fixture::<N>(&counting.inputs(), wrong),
        sdk_witness: tampered(&counting, wrong),
        circom: counting.circom(wrong),
    };
    let invalid = of_arity(&INVALID, N).map(|vector| {
        let honest = reference::poseidon(&vector.inputs()).expect("arity");
        Case {
            name: vector.name,
            holds: false,
            fixture: fixture::<N>(&vector.inputs(), vector.hash()),
            sdk_witness: SdkWitness::Tampered {
                honest: fixture::<N>(&vector.inputs(), honest),
                wires: vec![(hash_wire(N), vector.hash().into())],
            },
            circom: vector.circom(vector.hash()),
        }
    });
    honest.chain([off_by_one]).chain(invalid).collect()
}

struct Relation;

impl PerArity for Relation {
    type Output = (Visited<Accepts>, Visited<Accepts>);

    fn at<const N: usize>(&self) -> Self::Output {
        let cases = cases::<N>();
        (accepts_in_parallel(&compiled(N), &cases), expected(&cases))
    }
}

#[test]
fn circomlib_poseidon_accepts_exactly_the_sdks_claims_at_every_arity() {
    let (accepted, expected): (Vec<_>, Vec<_>) = every_arity(&Relation)
        .into_iter()
        .map(|(arity, (accepted, expected))| ((arity, accepted), (arity, expected)))
        .unzip();
    assert_eq!(accepted, expected);
}

struct Sizes;

impl PerArity for Sizes {
    type Output = ((Size, Size), (usize, usize));

    fn at<const N: usize>(&self) -> Self::Output {
        let compiled = compiled(N);
        let sdk = exported::<PoseidonClaim<N>>();
        (
            sizes::<PoseidonClaim<N>>(&compiled),
            (quadratic(&sdk), quadratic(&compiled.read_r1cs())),
        )
    }
}

#[test]
fn the_sizes_are_pinned_and_circomlib_has_exactly_three_more_sbox_rows_at_every_arity() {
    assert_eq!(
        every_arity(&Sizes),
        (1..=12)
            .map(|arity| (
                arity,
                (
                    (super::r1cs::SIZES[arity - 1], CIRCOM_SIZES[arity - 1]),
                    (sbox_rows(arity), sbox_rows(arity) + 3)
                )
            ))
            .collect::<Vec<_>>()
    );
}

#[test]
fn circomlib_poseidon_computes_the_pinned_hash_of_every_valid_vector() {
    let computed = std::thread::scope(|scope| {
        let runs: Vec<_> = VALID
            .iter()
            .map(|vector| {
                scope.spawn(move || {
                    let compiled = compiled(vector.arity());
                    compiled
                        .calculate(&vector.circom(Field::from(0u64)), Asserts::Ignore)
                        .map(|witness| witness[compiled.wire("main.poseidon.out")])
                })
            })
            .collect();
        VALID
            .iter()
            .zip(runs)
            .map(|(vector, run)| (vector.name, run.join().expect("a circom witness")))
            .collect::<Visited<_>>()
    });
    assert_eq!(
        computed,
        per_vector(&VALID, |vector| Ok(Fr::from(vector.hash())))
    );
}

#[test]
fn snarkjs_accepts_the_sdk_pair_and_rejects_a_tampered_hash_at_every_arity() {
    let work = WorkDir::new("gadgets-poseidon-snarkjs");
    let checked: Vec<_> = (1..=12)
        .map(|arity| {
            let vector = by_arity(arity);
            let (inputs, hash) = (vector.inputs(), vector.hash());
            let r1cs = work.write(
                &format!("poseidon-{arity}.r1cs"),
                &claim(&Export, &inputs, hash),
            );
            let honest = claim(&Assignment, &inputs, hash);
            let tampered = with_wires(
                honest.clone(),
                &[(hash_wire(arity), honest[hash_wire(arity)] + Fr::one())],
            );
            let honest = work.write(&format!("honest-{arity}.wtns"), &write_wtns(&honest));
            let tampered = work.write(&format!("tampered-{arity}.wtns"), &write_wtns(&tampered));
            (
                arity,
                snarkjs::wtns_check(&r1cs, &honest),
                snarkjs::wtns_check(&r1cs, &tampered),
            )
        })
        .collect();
    assert_eq!(
        checked,
        (1..=12)
            .map(|arity| (arity, WtnsCheck::Accepted, WtnsCheck::Rejected))
            .collect::<Vec<_>>()
    );
}

#[test]
fn snarkjs_proves_and_verifies_the_two_input_hash() {
    let work = WorkDir::new("gadgets-poseidon-groth16");
    let vector = by_arity(2);
    let (inputs, hash) = (vector.inputs(), vector.hash());
    let r1cs = work.write("sdk.r1cs", &claim(&Export, &inputs, hash));
    let wtns = work.write("sdk.wtns", &write_wtns(&claim(&Assignment, &inputs, hash)));
    assert_eq!(snarkjs::groth16(&work, &r1cs, &wtns), (true, json!([])));
}
