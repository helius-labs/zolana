use ark_bn254::Fr;
use ark_ff::{One, Zero};
use zk_program_sdk::circuit::Field;

use super::{
    fixtures::{chain, Chain, Chained, ConstantValues, RULE},
    vectors::{CHAIN_1, INVALID, VALID},
};
use crate::{
    gadgets::{
        hints::{inverse_hint, only_hints_tolerated, Site},
        reference,
    },
    harness::{
        digest::r1cs_digest,
        field::field,
        fixture::{
            assignment, breaks_rule, check_tampered, exported, per_vector, size, with_wires,
            CheckConstraints, Fixture, FreeVariables, ProverRefusal, Size, Visit,
        },
        iden3::{R1cs, R1csHeader},
    },
};

/// Size of the `Chain` of each length 0..=4. The first nonzero-able value
/// costs 2 rows for its zero test, 237 for Poseidon(0, value), whose chain
/// input and capacity element are constants in the first round (2 of 81
/// S-boxes free), and 1 for the select; every later value costs 2 + 240 + 1;
/// the claim adds 1 row. Each row but the claim allocates one variable.
pub const SIZES: [Size; 5] = [
    Size {
        constraints: 1,
        variables: 2,
    },
    Size {
        constraints: 241,
        variables: 243,
    },
    Size {
        constraints: 484,
        variables: 487,
    },
    Size {
        constraints: 727,
        variables: 731,
    },
    Size {
        constraints: 970,
        variables: 975,
    },
];

const DIGESTS: [&str; 5] = [
    "38d49c635a75f4cc52a116b43b00385fd0f3989a5222b61946a08b9a349a8f70",
    "c7d2507ac73d7d3f2d49e2749feb06d62651ce323586fdc86224a6b798f35bf5",
    "1475aaaed18a59fa3b2fe529b3617f71b4760d11e92b40988efe9a46c5e84b10",
    "a72cd5debdf8eb39949be03133dffea74afec833fd6cf4383b3f2a3e50003e7b",
    "a1afc64d0f6ce9c0732cc7d7d515e5b0933c23df2142e1d0625f902b72e84eaf",
];

const ZERO_TEST_LABEL: &str = "a hash chain of the nonzero values";

const ZERO_TEST: Site = Site {
    file: "sdk-tests/timelock-escrow/arkworks/zk-program-sdk/src/circuit/builtins/gadgets/hash_chain.rs",
    line: 12,
    column: 26,
};

pub fn chain_wire(len: usize) -> usize {
    len + 1
}

pub fn claim_row(len: usize) -> usize {
    SIZES[len].constraints - 1
}

struct Measure;

impl Visit<Chained> for Measure {
    type Output = (Size, String);

    fn visit<F: Fixture<Chained>>(&self, _fixture: &F) -> Self::Output {
        (size::<F>(), r1cs_digest::<F>())
    }
}

#[test]
fn every_length_exports_the_derived_size_and_the_pinned_digest() {
    let lengths = 0..=4;
    let formula: Vec<_> = lengths
        .clone()
        .map(|len: usize| match len {
            0 => Size {
                constraints: 1,
                variables: 2,
            },
            len => Size {
                constraints: 243 * len - 2,
                variables: 244 * len - 1,
            },
        })
        .collect();
    assert_eq!(
        (
            lengths
                .clone()
                .map(|len| chain(&Measure, &vec![Field::from(0u64); len], Field::from(0u64)))
                .collect::<Vec<_>>(),
            formula
        ),
        (
            SIZES
                .iter()
                .zip(DIGESTS)
                .map(|(size, digest)| (*size, digest.to_string()))
                .collect(),
            SIZES.to_vec()
        )
    );
}

#[test]
fn the_empty_chain_exports_exactly_the_claim_that_the_chain_is_zero() {
    let one = Fr::one();
    assert_eq!(
        exported::<Chain<0>>(),
        R1cs {
            header: R1csHeader::bn254(2, 0, 1, 1),
            a: vec![vec![(-one, 1)]],
            b: vec![vec![(one, 0)]],
            c: vec![vec![]],
            wire_labels: vec![0, 1],
        }
    );
}

#[test]
fn a_chain_of_constants_adds_no_row_and_no_variable() {
    let one = Fr::one();
    assert_eq!(
        exported::<ConstantValues>(),
        R1cs {
            header: R1csHeader::bn254(2, 0, 1, 1),
            a: vec![vec![(field(CHAIN_1).into(), 0), (-one, 1)]],
            b: vec![vec![(one, 0)]],
            c: vec![vec![]],
            wire_labels: vec![0, 1],
        }
    );
}

struct ClaimRow {
    len: usize,
    claimed: Option<Field>,
}

impl Visit<Chained> for ClaimRow {
    type Output = (Option<usize>, Option<usize>);

    fn visit<F: Fixture<Chained>>(&self, fixture: &F) -> Self::Output {
        let r1cs = exported::<F>();
        let honest = assignment(fixture);
        let wire = chain_wire(self.len);
        let claimed = self
            .claimed
            .map_or(honest[wire] + Fr::one(), |claimed| claimed.into());
        (
            r1cs.first_unsatisfied(&honest),
            r1cs.first_unsatisfied(&with_wires(honest.clone(), &[(wire, claimed)])),
        )
    }
}

#[test]
fn every_valid_vector_satisfies_every_row_and_a_chain_plus_one_breaks_the_claim_row() {
    assert_eq!(
        per_vector(&VALID, |vector| chain(
            &ClaimRow {
                len: vector.len(),
                claimed: None
            },
            &vector.values(),
            vector.chain()
        )),
        per_vector(&VALID, |vector| (None, Some(claim_row(vector.len()))))
    );
}

#[test]
fn every_invalid_claim_breaks_the_claim_row() {
    assert_eq!(
        per_vector(&INVALID, |vector| {
            let honest = reference::nonzero_hash_chain(&vector.values());
            chain(
                &ClaimRow {
                    len: vector.len(),
                    claimed: Some(vector.chain()),
                },
                &vector.values(),
                honest,
            )
        }),
        per_vector(&INVALID, |vector| (None, Some(claim_row(vector.len()))))
    );
}

#[test]
fn every_valid_vector_checks_exactly_the_placeholders_rows() {
    assert_eq!(
        per_vector(&VALID, |vector| chain(
            &CheckConstraints,
            &vector.values(),
            vector.chain()
        )),
        per_vector(&VALID, |vector| Ok(SIZES[vector.len()].constraints))
    );
}

struct Tampered {
    len: usize,
}

impl Visit<Chained> for Tampered {
    type Output = [Result<(), ProverRefusal>; 3];

    fn visit<F: Fixture<Chained>>(&self, fixture: &F) -> Self::Output {
        let honest = assignment(fixture);
        let wire = chain_wire(self.len);
        let skip_of_first = wire + 1;
        let flipped = if honest[skip_of_first].is_zero() {
            Fr::one()
        } else {
            Fr::zero()
        };
        [
            check_tampered(fixture, wire, honest[wire].into()),
            check_tampered(fixture, wire, (honest[wire] + Fr::one()).into()),
            check_tampered(fixture, skip_of_first, flipped.into()),
        ]
    }
}

#[test]
fn the_proving_rows_refuse_a_tampered_chain_and_a_flipped_zero_test() {
    let nonempty = || VALID.iter().filter(|vector| vector.len() > 0);
    assert_eq!(
        nonempty()
            .map(|vector| (
                vector.name,
                chain(
                    &Tampered { len: vector.len() },
                    &vector.values(),
                    vector.chain()
                )
            ))
            .collect::<Vec<_>>(),
        nonempty()
            .map(|vector| (
                vector.name,
                [
                    Ok(()),
                    Err(breaks_rule(claim_row(vector.len()), RULE)),
                    Err(breaks_rule(0, ZERO_TEST_LABEL)),
                ]
            ))
            .collect::<Vec<_>>()
    );
}

/// Rows and private variables before the zero test of value `index`: the
/// first value costs 240 of each, every later one 243.
fn before(index: usize) -> usize {
    match index {
        0 => 0,
        index => 240 + 243 * (index - 1),
    }
}

#[test]
fn no_private_variable_is_free_and_only_the_hint_of_each_zero_value_is_tolerated() {
    assert_eq!(
        per_vector(&VALID, |vector| chain(
            &FreeVariables,
            &vector.values(),
            vector.chain()
        )),
        per_vector(&VALID, |vector| {
            let size = SIZES[vector.len()];
            let hints = vector
                .values
                .iter()
                .enumerate()
                .filter(|(_, value)| **value == "0")
                .map(|(index, _)| {
                    let hint = vector.len() + 2 + before(index);
                    inverse_hint(ZERO_TEST, before(index) + 2, hint)
                })
                .collect();
            only_hints_tolerated(size.constraints, size.variables - 1, hints)
        })
    );
}
