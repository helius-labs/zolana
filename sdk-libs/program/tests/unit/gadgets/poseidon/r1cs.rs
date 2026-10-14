use ark_bn254::Fr;
use ark_ff::One;
use zolana_program::{circuit::Field, ProverError, ZkCircuit};

use super::{
    fixtures::{
        claim, counting, ConstantInputs, Hashed, PoseidonClaim, PARTIAL_ROUNDS, RULE, SUPPORTED,
    },
    vectors::{by_arity, HASH_1_2, INVALID, VALID},
};
use crate::{
    gadgets::reference,
    harness::{
        digest::r1cs_digest,
        field::field,
        fixture::{
            assignment, breaks_rule, check_constraints, check_tampered, exported, no_free_variable,
            per_vector, prover_refusal, size, with_wires, Assignment, CheckConstraints, Fixture,
            FreeVariables, ProverRefusal, Size, Visit,
        },
        iden3::{R1cs, R1csHeader},
        normalize::{constraints, Constraint},
    },
};

pub const SIZES: [Size; 12] = [
    Size {
        constraints: 214,
        variables: 216,
    },
    Size {
        constraints: 241,
        variables: 244,
    },
    Size {
        constraints: 262,
        variables: 266,
    },
    Size {
        constraints: 298,
        variables: 303,
    },
    Size {
        constraints: 322,
        variables: 328,
    },
    Size {
        constraints: 355,
        variables: 362,
    },
    Size {
        constraints: 382,
        variables: 390,
    },
    Size {
        constraints: 403,
        variables: 412,
    },
    Size {
        constraints: 418,
        variables: 428,
    },
    Size {
        constraints: 460,
        variables: 471,
    },
    Size {
        constraints: 466,
        variables: 478,
    },
    Size {
        constraints: 505,
        variables: 518,
    },
];

const DIGESTS: [&str; 12] = [
    "255d86a43173d26091511e542bab129737620b234e45b894ede85c3a0dfc5238",
    "711d50b9c43ed73114bb11dc89af6d3f0f937429ee7af463c33d449a5b10403e",
    "ac98ce9048336c7edfa436ba7929655e6b63914c1856516c537c27f315aa1b39",
    "290ef19ece47e34f63d1ff3e28697563d954012736ead88a3bb567354530ad6f",
    "9a893c47f7f04706eb722fa2bf9cec95f30b40655be0ed4479b3d4d529a899c4",
    "f43d64bc7ed92377a57871aeb5602105af71471d12f3701b9068e1f5d4d36c67",
    "32dccd53eb66cd89ee422c446513f7bcf297bbb4ed89e7e65e9540d1a223d8de",
    "26ff64cdba3cccd343a0d99cf1da936f39c71c0ce45f9fa397a050ca49de2fc6",
    "ef82326803993cd6402f23b885adc0b2f2ef40726d27216756d151ef4e4c14dc",
    "e291a69995442016c7c67320073141921db575d6c868a23ed87bbffa5bd31b75",
    "5a9388c77aab01ba569afe7fa510c0344103d455cde23b07ec4425c5e1f3a615",
    "ae0be81b9f06b7ce87c656e7a6ba6c35d840abbdb24e55e2c85fe59f998b645e",
];

const UNSUPPORTED: ProverRefusal = ("CircuitError.UnsupportedHashInputCount", None, None);

/// Every S-box on a variable costs 3 rows (x^2, x^4, x^5). Of the
/// 8 * (arity + 1) full-round and the partial-round S-boxes exactly one is
/// on a constant: the capacity element's in the first round.
pub fn sbox_rows(arity: usize) -> usize {
    3 * (8 * (arity + 1) + PARTIAL_ROUNDS[arity - 1] - 1)
}

pub fn hash_wire(arity: usize) -> usize {
    arity + 1
}

pub fn claim_row(arity: usize) -> usize {
    SIZES[arity - 1].constraints - 1
}

struct Measure;

impl Visit<Hashed> for Measure {
    type Output = (Size, usize, String);

    fn visit<F: Fixture<Hashed>>(&self, _fixture: &F) -> Self::Output {
        let quadratic = constraints(&exported::<F>())
            .iter()
            .filter(|constraint| matches!(constraint, Constraint::Quadratic { .. }))
            .count();
        (size::<F>(), quadratic, r1cs_digest::<F>())
    }
}

#[test]
fn every_arity_exports_three_rows_per_variable_sbox_plus_the_claim_row() {
    let formula: Vec<_> = SUPPORTED
        .map(|arity| {
            let rows = sbox_rows(arity);
            let size = Size {
                constraints: rows + 1,
                variables: 1 + arity + 1 + rows,
            };
            (arity, size, rows)
        })
        .collect();
    let measured: Vec<_> = SUPPORTED
        .map(|arity| {
            let (size, quadratic, _) = claim(&Measure, &counting(arity), Field::from(0u64));
            (arity, size, quadratic)
        })
        .collect();
    let pinned: Vec<_> = SUPPORTED
        .map(|arity| {
            let size = SIZES[arity - 1];
            (arity, size, size.constraints - 1)
        })
        .collect();
    assert_eq!((measured, formula), (pinned.clone(), pinned));
}

#[test]
fn every_arity_exports_the_pinned_r1cs_digest() {
    assert_eq!(
        SUPPORTED
            .map(|arity| claim(&Measure, &counting(arity), Field::from(0u64)).2)
            .collect::<Vec<_>>(),
        DIGESTS.map(String::from).to_vec()
    );
}

#[test]
fn a_hash_of_constants_adds_no_row_and_no_variable() {
    let one = Fr::one();
    assert_eq!(
        exported::<ConstantInputs>(),
        R1cs {
            header: R1csHeader::bn254(2, 0, 1, 1),
            a: vec![vec![(field(HASH_1_2).into(), 0), (-one, 1)]],
            b: vec![vec![(one, 0)]],
            c: vec![vec![]],
            wire_labels: vec![0, 1],
        }
    );
}

#[test]
fn the_assignment_is_the_constant_one_the_inputs_and_the_hash_then_the_sbox_witnesses() {
    assert_eq!(
        per_vector(&VALID, |vector| {
            let witness = claim(&Assignment, &vector.inputs(), vector.hash());
            (
                witness[..=hash_wire(vector.arity())].to_vec(),
                witness.len(),
            )
        }),
        per_vector(&VALID, |vector| {
            let prefix: Vec<Fr> = [Fr::one()]
                .into_iter()
                .chain(vector.inputs().into_iter().map(Fr::from))
                .chain([Fr::from(vector.hash())])
                .collect();
            (prefix, SIZES[vector.arity() - 1].variables)
        })
    );
}

struct ClaimRow {
    arity: usize,
    claimed: Option<Field>,
}

impl Visit<Hashed> for ClaimRow {
    type Output = (Option<usize>, Option<usize>);

    fn visit<F: Fixture<Hashed>>(&self, fixture: &F) -> Self::Output {
        let r1cs = exported::<F>();
        let honest = assignment(fixture);
        let wire = hash_wire(self.arity);
        let claimed = self
            .claimed
            .map_or(honest[wire] + Fr::one(), |claimed| claimed.into());
        let dishonest = with_wires(honest.clone(), &[(wire, claimed)]);
        (
            r1cs.first_unsatisfied(&honest),
            r1cs.first_unsatisfied(&dishonest),
        )
    }
}

#[test]
fn every_valid_vector_satisfies_every_row_and_a_hash_plus_one_breaks_the_claim_row() {
    assert_eq!(
        per_vector(&VALID, |vector| claim(
            &ClaimRow {
                arity: vector.arity(),
                claimed: None
            },
            &vector.inputs(),
            vector.hash()
        )),
        per_vector(&VALID, |vector| (None, Some(claim_row(vector.arity()))))
    );
}

#[test]
fn every_invalid_claim_breaks_the_claim_row() {
    assert_eq!(
        per_vector(&INVALID, |vector| {
            let honest = reference::poseidon(&vector.inputs()).expect("a supported arity");
            claim(
                &ClaimRow {
                    arity: vector.arity(),
                    claimed: Some(vector.hash()),
                },
                &vector.inputs(),
                honest,
            )
        }),
        per_vector(&INVALID, |vector| (None, Some(claim_row(vector.arity()))))
    );
}

#[test]
fn every_valid_vector_checks_exactly_the_placeholders_rows() {
    assert_eq!(
        per_vector(&VALID, |vector| claim(
            &CheckConstraints,
            &vector.inputs(),
            vector.hash()
        )),
        per_vector(&VALID, |vector| Ok(SIZES[vector.arity() - 1].constraints))
    );
}

struct Tampered {
    arity: usize,
}

impl Visit<Hashed> for Tampered {
    type Output = [Result<(), ProverRefusal>; 3];

    fn visit<F: Fixture<Hashed>>(&self, fixture: &F) -> Self::Output {
        let honest = assignment(fixture);
        let wire = hash_wire(self.arity);
        [
            check_tampered(fixture, wire, honest[wire].into()),
            check_tampered(fixture, wire, (honest[wire] + Fr::one()).into()),
            check_tampered(fixture, wire + 1, (honest[wire + 1] + Fr::one()).into()),
        ]
    }
}

#[test]
fn the_proving_rows_accept_the_honest_hash_and_refuse_a_tampered_hash_or_sbox() {
    assert_eq!(
        per_vector(&VALID, |vector| claim(
            &Tampered {
                arity: vector.arity()
            },
            &vector.inputs(),
            vector.hash()
        )),
        per_vector(&VALID, |vector| [
            Ok(()),
            Err(breaks_rule(claim_row(vector.arity()), RULE)),
            Err(breaks_rule(0, "a poseidon hash")),
        ])
    );
}

#[test]
fn no_private_variable_is_free_at_any_arity() {
    assert_eq!(
        SUPPORTED
            .map(|arity| {
                let vector = by_arity(arity);
                claim(&FreeVariables, &vector.inputs(), vector.hash())
            })
            .collect::<Vec<_>>(),
        SIZES
            .map(|size| no_free_variable(size.constraints, size.variables - 1))
            .to_vec()
    );
}

#[test]
fn a_fixture_of_an_unsupported_arity_neither_exports_nor_checks() {
    let refusal = |result: Result<Vec<u8>, ProverError>| result.map(|_| ()).map_err(prover_refusal);
    assert_eq!(
        (
            refusal(PoseidonClaim::<0>::export_r1cs()),
            refusal(PoseidonClaim::<13>::export_r1cs()),
            check_constraints(&PoseidonClaim::<0> {
                inputs: [],
                hash: Field::from(0u64),
            }),
            check_constraints(&PoseidonClaim::<13> {
                inputs: [Field::from(1u64); 13],
                hash: Field::from(0u64),
            }),
        ),
        (
            Err(UNSUPPORTED),
            Err(UNSUPPORTED),
            Err(UNSUPPORTED),
            Err(UNSUPPORTED),
        )
    );
}
