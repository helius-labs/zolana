use ark_bn254::Fr;
use ark_ff::{One, Zero};
use zolana_program::circuit::Field;

use super::{
    fixtures::{chain, reference_chain, Chain, Chained, ConstantValues, RULE},
    vectors::{CHAIN_1_2, INVALID, VALID},
};
use crate::{
    gadgets::hints::{inverse_hint, only_hints_tolerated, Site},
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

/// Rows of a zero test, which allocates its bit and its inverse hint.
const ZERO_TEST_ROWS: usize = 2;

/// Rows of a select: one product.
const SELECT_ROWS: usize = 1;

/// Rows of `Poseidon(chain, value)` over a variable chain: 8 full rounds of 3
/// S-boxes and 57 partial rounds of 1, less the S-box of the capacity element,
/// a constant in the first round, at 3 products per S-box.
const POSEIDON_ROWS: usize = 3 * (8 * 3 + 57 - 1);

/// The first value meets the chain while it is still the constant zero: its
/// zero test and the select of the chain over the value, with no zero test of
/// the chain and no Poseidon.
const FIRST_VALUE_ROWS: usize = ZERO_TEST_ROWS + SELECT_ROWS;

/// Every later value meets a variable chain: its zero test, the chain's zero
/// test, `Poseidon(chain, value)`, the select of the value over the hash when
/// the chain is zero and the select of the chain over that when the value is
/// zero.
const LATER_VALUE_ROWS: usize = 2 * ZERO_TEST_ROWS + POSEIDON_ROWS + 2 * SELECT_ROWS;

/// Size of the `Chain` of each length 0..=4, as `derived` counts it.
pub const SIZES: [Size; 5] = [
    Size {
        constraints: 1,
        variables: 2,
    },
    Size {
        constraints: 4,
        variables: 6,
    },
    Size {
        constraints: 250,
        variables: 253,
    },
    Size {
        constraints: 496,
        variables: 500,
    },
    Size {
        constraints: 742,
        variables: 747,
    },
];

const DIGESTS: [&str; 5] = [
    "38d49c635a75f4cc52a116b43b00385fd0f3989a5222b61946a08b9a349a8f70",
    "5b78ecf52778a4bbf9ee2bf29708fc720d97a5c32a80a76c1dc7d2b6510b631e",
    "f0d20b8bffd3abd9ddb725a3f6a3a2412a2594976729c8020d07a068da05a395",
    "c4620bd015eea28bf3ddeac1f6ef533c7ab1a54f88837945cc5cc23016f658e3",
    "ee366746b8c1ab3071f77ffb51052b55b5dfdff8c3bd2631b4de2da00da262fe",
];

const ZERO_TEST_LABEL: &str = "a hash chain of the nonzero values";

const VALUE_ZERO_TEST: Site = Site {
    file: "sdk-libs/program/src/circuit/builtins/gadgets/hash_chain.rs",
    line: 12,
    column: 26,
};

const CHAIN_ZERO_TEST: Site = Site {
    file: "sdk-libs/program/src/circuit/builtins/gadgets/hash_chain.rs",
    line: 16,
    column: 32,
};

pub fn pinned(len: usize) -> Size {
    *SIZES.get(len).expect("a pinned length")
}

pub fn chain_wire(len: usize) -> usize {
    len + 1
}

pub fn claim_row(len: usize) -> usize {
    pinned(len).constraints - 1
}

/// Rows before value `index`, the first zero test of that value.
fn before(index: usize) -> usize {
    match index {
        0 => 0,
        index => FIRST_VALUE_ROWS + LATER_VALUE_ROWS * (index - 1),
    }
}

/// The first row of the chain's zero test at value `index`, from the second
/// value on.
fn chain_zero_test(index: usize) -> usize {
    before(index) + ZERO_TEST_ROWS
}

/// The rows of every value and the claim; the constant one, the values, the
/// claimed chain, and one private variable for every row but the claim.
fn derived(len: usize) -> Size {
    Size {
        constraints: before(len) + 1,
        variables: 1 + len + 1 + before(len),
    }
}

/// The private variable allocated with `row`, after the values and the
/// claimed chain; its wire is one higher.
fn variable_of_row(len: usize, row: usize) -> usize {
    len + 1 + row
}

fn wire_of_row(len: usize, row: usize) -> usize {
    variable_of_row(len, row) + 1
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
    assert_eq!(
        (
            lengths
                .clone()
                .map(|len| chain(&Measure, &vec![Field::from(0u64); len], Field::from(0u64)))
                .collect::<Vec<_>>(),
            lengths.map(derived).collect::<Vec<_>>()
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
            a: vec![vec![(field(CHAIN_1_2).into(), 0), (-one, 1)]],
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
        let chained = *honest.get(wire).expect("the chain");
        let claimed = self
            .claimed
            .map_or(chained + Fr::one(), |claimed| claimed.into());
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
            let honest = reference_chain(&vector.values());
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
        per_vector(&VALID, |vector| Ok(pinned(vector.len()).constraints))
    );
}

/// The first rows of every zero test in order: the value's at every index,
/// then the chain's from the second index on.
fn zero_tests(len: usize) -> Vec<usize> {
    (0..len)
        .map(before)
        .chain((1..len).map(chain_zero_test))
        .collect()
}

struct Tampered {
    len: usize,
}

impl Visit<Chained> for Tampered {
    type Output = Vec<Result<(), ProverRefusal>>;

    fn visit<F: Fixture<Chained>>(&self, fixture: &F) -> Self::Output {
        let honest = assignment(fixture);
        let at = |wire: usize| *honest.get(wire).expect("a witness wire");
        let wire = chain_wire(self.len);
        let flipped = zero_tests(self.len).into_iter().map(|row| {
            let bit = wire_of_row(self.len, row);
            let flipped = if at(bit).is_zero() {
                Fr::one()
            } else {
                Fr::zero()
            };
            check_tampered(fixture, bit, flipped.into())
        });
        [
            check_tampered(fixture, wire, at(wire).into()),
            check_tampered(fixture, wire, (at(wire) + Fr::one()).into()),
        ]
        .into_iter()
        .chain(flipped)
        .collect()
    }
}

#[test]
fn the_proving_rows_refuse_a_tampered_chain_and_every_flipped_zero_test() {
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
                [Ok(()), Err(breaks_rule(claim_row(vector.len()), RULE))]
                    .into_iter()
                    .chain(
                        zero_tests(vector.len())
                            .into_iter()
                            .map(|row| Err(breaks_rule(row, ZERO_TEST_LABEL)))
                    )
                    .collect::<Vec<_>>()
            ))
            .collect::<Vec<_>>()
    );
}

#[test]
fn no_private_variable_is_free_and_only_the_hints_of_zero_values_and_zero_chains_are_tolerated() {
    let zero = Field::from(0u64);
    assert_eq!(
        per_vector(&VALID, |vector| chain(
            &FreeVariables,
            &vector.values(),
            vector.chain()
        )),
        per_vector(&VALID, |vector| {
            let len = vector.len();
            let values = vector.values();
            let hint = |site: Site, row: usize| {
                inverse_hint(site, row + ZERO_TEST_ROWS, variable_of_row(len, row + 1))
            };
            let hints = values
                .iter()
                .enumerate()
                .flat_map(|(index, value)| {
                    let earlier = values.get(..index).expect("the earlier values");
                    let zero_value = (*value == zero).then(|| hint(VALUE_ZERO_TEST, before(index)));
                    let zero_chain = (index > 0 && reference_chain(earlier) == zero)
                        .then(|| hint(CHAIN_ZERO_TEST, chain_zero_test(index)));
                    zero_value.into_iter().chain(zero_chain)
                })
                .collect();
            let size = pinned(len);
            only_hints_tolerated(size.constraints, size.variables - 1, hints)
        })
    );
}
