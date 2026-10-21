use ark_bn254::Fr;
use ark_ff::One;
use zolana_program::{circuit::Field, testing, CircuitError, ZkCircuit};
use zolana_transaction::Mint;

use super::{
    fixtures::{
        AssetHash, Equal, EqualIf, EqualsConstant, HashedTwice, IsEqual, NotEqual, Pair, Selected,
        Single, SolHash, CONSTANT_MINT, EQUAL_BROKEN, EQUAL_RULE, HASH_RULE, HASH_WIRE,
        IS_EQUAL_RULE,
    },
    vectors::{distinct_pairs, Vector, MINTS},
};
use crate::{
    harness::{
        digest::r1cs_digest,
        fixture::{
            assignment, breaks_rule, check_constraints, check_private_variables, check_tampered,
            exported, first_unsatisfied, no_free_variable, per_vector, prover_refusal, size,
            with_wires, Refusal, Size,
        },
        iden3::{R1cs, R1csHeader},
    },
    protocol::owner::wires::{allocated, check, wire},
};

pub const HASH_SIZE: Size = Size {
    constraints: 529,
    variables: 530,
};
pub const HASH_ROW: usize = 528;
pub const HASH_DIGEST: &str = "7962528c9518dc8cfc42e725d60daece87503868f6ed62fd749c2e49fac013c7";
pub const POSEIDON_2_ROWS: usize = 240;
const BYTE_RULE: &str = "a byte proof input does not fit in 8 bits";
const RANGE_ROWS: usize = 9;
pub const MINT_ROWS: usize = 32 * RANGE_ROWS;

fn hash_fixture(vector: &Vector) -> AssetHash {
    AssetHash {
        hash: vector.hash(),
        mint: vector.mint,
    }
}

fn first_31_bytes_differ(left: &Vector, right: &Vector) -> bool {
    left.mint.asset.as_array()[..31] != right.mint.asset.as_array()[..31]
}

#[test]
fn the_asset_hash_fixture_has_a_pinned_size_digest_and_no_public_input() {
    let r1cs = exported::<AssetHash>();
    assert_eq!(
        (
            size::<AssetHash>(),
            r1cs_digest::<AssetHash>(),
            r1cs.header.public_inputs,
            r1cs.header.public_outputs,
            r1cs.header.private_inputs,
        ),
        (HASH_SIZE, HASH_DIGEST.to_string(), 0, 0, 529)
    );
}

#[test]
fn every_mint_satisfies_every_row_with_its_native_hash_on_the_claim_wire() {
    assert_eq!(
        per_vector(&MINTS, |vector| {
            let fixture = hash_fixture(vector);
            let honest = assignment(&fixture);
            (
                check_constraints(&fixture),
                first_unsatisfied::<AssetHash>(&honest),
                honest[HASH_WIRE],
            )
        }),
        per_vector(&MINTS, |vector| (
            Ok(HASH_SIZE.constraints),
            None,
            Fr::from(vector.hash())
        ))
    );
}

#[test]
fn a_claimed_hash_of_another_mint_breaks_exactly_the_hash_row() {
    let pairs = distinct_pairs();
    assert_eq!(
        pairs
            .iter()
            .map(|(left, right)| {
                let fixture = hash_fixture(left);
                let tampered =
                    with_wires(assignment(&fixture), &[(HASH_WIRE, Fr::from(right.hash()))]);
                (
                    first_unsatisfied::<AssetHash>(&tampered),
                    check_tampered(&fixture, HASH_WIRE, right.hash()),
                )
            })
            .collect::<Vec<_>>(),
        vec![(Some(HASH_ROW), Err(breaks_rule(HASH_ROW, HASH_RULE))); pairs.len()]
    );
}

#[test]
fn a_mint_and_its_clone_share_one_hash_so_the_second_claim_costs_one_row() {
    let vector = &MINTS[3];
    assert_eq!(
        (
            size::<HashedTwice>(),
            check_constraints(&HashedTwice {
                hash: vector.hash(),
                mint: vector.mint,
            }),
        ),
        (
            Size {
                constraints: HASH_SIZE.constraints + 1,
                variables: HASH_SIZE.variables,
            },
            Ok(HASH_SIZE.constraints + 1),
        )
    );
}

#[test]
fn every_mint_byte_is_range_checked_to_8_bits() {
    let fixture = hash_fixture(&MINTS[3]);
    let honest = assignment(&fixture);
    let bytes = allocated(&fixture, "a byte proof input");
    let refused: Vec<_> = bytes
        .iter()
        .map(|byte| {
            let widened = honest[*byte] + Fr::from(256u64);
            check_tampered(&fixture, *byte, Field::from(widened))
        })
        .collect();
    assert_eq!(
        (bytes.len(), refused),
        (
            32,
            (0..32)
                .map(|index| Err(breaks_rule(index * RANGE_ROWS + 8, BYTE_RULE)))
                .collect::<Vec<_>>()
        )
    );
}

#[test]
fn no_private_variable_of_the_asset_hash_fixture_is_free() {
    assert_eq!(
        per_vector(&MINTS, |vector| check_private_variables(&hash_fixture(
            vector
        ))),
        per_vector(&MINTS, |_| no_free_variable(529, 529))
    );
}

#[test]
fn a_constant_asset_hash_is_one_row_with_the_hash_on_variable_zero() {
    let sol = MINTS[0].hash();
    let one = Fr::one();
    assert_eq!(
        (
            exported::<SolHash>(),
            check_constraints(&SolHash { hash: sol }),
            testing::check_tampered(
                &SolHash { hash: sol },
                testing::Tamper::PrivateVariable {
                    index: 0,
                    value: MINTS[1].hash(),
                },
            )
            .map_err(prover_refusal),
        ),
        (
            R1cs {
                header: R1csHeader::bn254(2, 0, 1, 1),
                a: vec![vec![(Fr::from(sol), 0), (-one, 1)]],
                b: vec![vec![(one, 0)]],
                c: vec![vec![]],
                wire_labels: vec![0, 1],
            },
            Ok(1),
            Err(breaks_rule(0, HASH_RULE)),
        )
    );
}

#[test]
fn a_mint_other_than_the_constant_breaks_a_comparison_row() {
    let r1cs = exported::<EqualsConstant>();
    assert_eq!(
        (
            size::<EqualsConstant>(),
            size::<Single>(),
            per_vector(&MINTS, |vector| r1cs
                .first_unsatisfied(&assignment(&Single { mint: vector.mint }))),
        ),
        (
            Size {
                constraints: MINT_ROWS + 2,
                variables: 289,
            },
            Size {
                constraints: MINT_ROWS,
                variables: 289,
            },
            per_vector(&MINTS, |vector| if vector.mint == CONSTANT_MINT {
                None
            } else if vector.mint.asset.as_array()[..31] != CONSTANT_MINT.asset.as_array()[..31] {
                Some(MINT_ROWS)
            } else {
                Some(MINT_ROWS + 1)
            }),
        )
    );
}

#[test]
fn assert_equal_compares_the_two_packed_chunks_in_one_row_each() {
    let pairs = distinct_pairs();
    let r1cs = exported::<Equal>();
    let equal = |vector: &Vector| Pair {
        left: vector.mint,
        right: vector.mint,
    };
    assert_eq!(
        (
            size::<Equal>(),
            size::<Pair>(),
            per_vector(&MINTS, |vector| r1cs
                .first_unsatisfied(&assignment(&equal(vector)))),
            pairs
                .iter()
                .map(|(left, right)| r1cs.first_unsatisfied(&assignment(&Pair {
                    left: left.mint,
                    right: right.mint,
                })))
                .collect::<Vec<_>>(),
            check(
                &Equal {
                    left: MINTS[1].mint,
                    right: MINTS[1].mint,
                },
                EQUAL_RULE
            )
            .rows,
        ),
        (
            Size {
                constraints: 2 * MINT_ROWS + 2,
                variables: 577,
            },
            Size {
                constraints: 2 * MINT_ROWS,
                variables: 577,
            },
            per_vector(&MINTS, |_| None),
            pairs
                .iter()
                .map(|(left, right)| Some(if first_31_bytes_differ(left, right) {
                    2 * MINT_ROWS
                } else {
                    2 * MINT_ROWS + 1
                }))
                .collect::<Vec<_>>(),
            2 * MINT_ROWS..2 * MINT_ROWS + 1,
        )
    );
}

#[test]
fn assert_equal_if_refuses_distinct_mints_once_the_condition_is_set() {
    let pairs = distinct_pairs();
    assert_eq!(
        pairs
            .iter()
            .map(|(left, right)| {
                let fixture = EqualIf {
                    left: left.mint,
                    right: right.mint,
                    condition: false,
                };
                let condition = wire(&fixture, "a bool proof input");
                (
                    check_constraints(&fixture),
                    check_tampered(&fixture, condition, Field::from(1u64)),
                )
            })
            .collect::<Vec<_>>(),
        pairs
            .iter()
            .map(|(left, right)| (
                Ok(2 * MINT_ROWS + 3),
                Err(breaks_rule(
                    if first_31_bytes_differ(left, right) {
                        2 * MINT_ROWS + 1
                    } else {
                        2 * MINT_ROWS + 2
                    },
                    EQUAL_RULE
                ))
            ))
            .collect::<Vec<_>>()
    );
}

#[test]
fn assert_not_equal_refuses_equal_mints_while_proving_with_exactly_the_rule() {
    let pairs = distinct_pairs();
    let proving = |left: Mint, right: Mint| {
        NotEqual { left, right }
            .check_constraints()
            .map_err(|error| error.circuit_error().map(outcome_of))
    };
    assert_eq!(
        (
            size::<NotEqual>(),
            per_vector(&MINTS, |vector| proving(vector.mint, vector.mint)),
            pairs
                .iter()
                .map(|(left, right)| proving(left.mint, right.mint))
                .collect::<Vec<_>>(),
        ),
        (
            Size {
                constraints: 2 * MINT_ROWS + 7,
                variables: 583,
            },
            per_vector(&MINTS, |_| Err(Some(EQUAL_BROKEN))),
            vec![Ok(2 * MINT_ROWS + 7); pairs.len()],
        )
    );
}

fn outcome_of(error: &CircuitError) -> Refusal {
    (error.name(), error.broken_rule(), error.location().file())
}

#[test]
fn a_flipped_equality_claim_breaks_exactly_the_claim_row() {
    let cases: Vec<(Vector, Vector, bool)> = MINTS
        .iter()
        .map(|vector| (*vector, *vector, true))
        .chain(distinct_pairs().into_iter().map(|(l, r)| (l, r, false)))
        .collect();
    let last_row = size::<IsEqual>().constraints - 1;
    assert_eq!(
        cases
            .iter()
            .map(|(left, right, claimed)| {
                let fixture = IsEqual {
                    left: left.mint,
                    right: right.mint,
                    claimed: *claimed,
                };
                let claim = wire(&fixture, "a bool proof input");
                (
                    check_constraints(&fixture),
                    check_tampered(&fixture, claim, Field::from(u64::from(!claimed))),
                )
            })
            .collect::<Vec<_>>(),
        vec![(Ok(last_row + 1), Err(breaks_rule(last_row, IS_EQUAL_RULE))); cases.len()]
    );
}

#[test]
fn select_multiplies_once_per_byte_and_a_flipped_condition_breaks_the_first_differing_byte() {
    let pairs = distinct_pairs();
    let first_select_row = 2 * MINT_ROWS + 1;
    let fixture = |condition: bool, (left, right): &(Vector, Vector)| Selected {
        hash: if condition { left.hash() } else { right.hash() },
        condition,
        if_true: left.mint,
        if_false: right.mint,
    };
    let first_differing_byte = |(left, right): &(Vector, Vector)| {
        left.mint
            .asset
            .as_array()
            .iter()
            .zip(right.mint.asset.as_array())
            .position(|(left, right)| left != right)
            .expect("distinct mints")
    };
    let checked: Vec<_> = pairs
        .iter()
        .flat_map(|pair| {
            [true, false].map(|condition| {
                let selected = fixture(condition, pair);
                let condition_wire = wire(&selected, "a bool proof input");
                let flipped = with_wires(
                    assignment(&selected),
                    &[(condition_wire, Fr::from(u64::from(!condition)))],
                );
                (
                    check_constraints(&selected),
                    first_unsatisfied::<Selected>(&flipped),
                )
            })
        })
        .collect();
    assert_eq!(
        (size::<Selected>(), checked),
        (
            Size {
                constraints: 2 * MINT_ROWS + 1 + 32 + POSEIDON_2_ROWS + 1,
                variables: 851,
            },
            pairs
                .iter()
                .flat_map(|pair| {
                    let row = Some(first_select_row + first_differing_byte(pair));
                    [(Ok(850), row), (Ok(850), row)]
                })
                .collect::<Vec<_>>()
        )
    );
}
