use ark_bn254::Fr;
use zk_program_sdk::{circuit::Field, Owner as ClientOwner};
use zolana_hasher::primitives::{P256_OWNER_TAG, SOLANA_OWNER_TAG};

use super::{
    fixtures::{
        HashedTwice, Identity, Instantiated, KeyEqual, KeyEqualIf, KeyIsEqual, KeySelected,
        OwnerEqual, OwnerEqualIf, OwnerHash, OwnerIsEqual, OwnerSelected, Pair, PreimageHash,
        CLAIM_WIRE, EQUAL_RULE, HASH_RULE, IDENTITY_RULE, IS_EQUAL_RULE,
    },
    native::TAG_RULE,
    vectors::{hash_field, identity_field, keys, neighbours, nullifier_pk, preimage},
    wires::{before_check, check, wire},
};
use crate::{
    harness::{
        digest::r1cs_digest,
        fixture::{
            assignment, breaks_rule, check_constraints, check_private_variables, check_tampered,
            export, first_unsatisfied, no_free_variable, per_vector, size, with_wires, Size,
        },
    },
    protocol::asset::{r1cs::MINT_ROWS, vectors::field_of},
};

pub const HASH_SIZE: Size = Size {
    constraints: 771,
    variables: 773,
};
pub const HASH_ROW: usize = 770;
const PAIR_ROWS: usize = 2 * (MINT_ROWS + 2);
pub const HASH_DIGEST: &str = "bd842f3ecd45e2b019a118ec3f3f100c94157c6c6dce5027ac93918164360b56";

fn base() -> ClientOwner {
    preimage(SOLANA_OWNER_TAG, [3u8; 32], nullifier_pk(4))
}

fn tag_product(tag: u64) -> Fr {
    (Fr::from(tag) - Fr::from(u64::from(SOLANA_OWNER_TAG)))
        * (Fr::from(tag) - Fr::from(u64::from(P256_OWNER_TAG)))
}

fn pair_cases() -> Vec<(&'static str, ClientOwner, ClientOwner)> {
    let base = base();
    std::iter::once(("the same owner", base, base))
        .chain(
            neighbours(&base)
                .into_iter()
                .map(move |(name, neighbour)| (name, base, neighbour)),
        )
        .collect()
}

#[test]
fn the_owner_hash_fixtures_have_pinned_sizes_and_digest() {
    assert_eq!(
        (
            size::<OwnerHash>(),
            size::<Identity>(),
            r1cs_digest::<OwnerHash>(),
            export::<PreimageHash>() == export::<OwnerHash>(),
        ),
        (
            HASH_SIZE,
            Size {
                constraints: 531,
                variables: 533,
            },
            HASH_DIGEST.to_string(),
            true,
        )
    );
}

#[test]
fn every_key_satisfies_every_row_with_its_native_hash_on_the_claim_wire() {
    let keys = keys();
    assert_eq!(
        per_vector(&keys, |key| {
            let fixture = OwnerHash {
                hash: field_of(&key.native_hash()),
                owner: key.address,
            };
            let identity = Identity {
                identity: field_of(&key.native_identity()),
                owner: key.address,
            };
            let honest = assignment(&fixture);
            (
                check_constraints(&fixture),
                check_constraints(&identity),
                first_unsatisfied::<OwnerHash>(&honest),
                honest[CLAIM_WIRE],
            )
        }),
        per_vector(&keys, |key| (
            Ok(HASH_SIZE.constraints),
            Ok(531),
            None,
            Fr::from(field_of(&key.native_hash()))
        ))
    );
}

#[test]
fn a_claimed_hash_or_identity_of_another_key_breaks_exactly_the_claim_row() {
    let keys = keys();
    let other = |index: usize| &keys[(index + 1) % keys.len()];
    let refused: Vec<_> = keys
        .iter()
        .enumerate()
        .map(|(index, key)| {
            let hash = OwnerHash {
                hash: field_of(&key.native_hash()),
                owner: key.address,
            };
            let identity = Identity {
                identity: field_of(&key.native_identity()),
                owner: key.address,
            };
            (
                check_tampered(&hash, CLAIM_WIRE, field_of(&other(index).native_hash())),
                check_tampered(
                    &identity,
                    CLAIM_WIRE,
                    field_of(&other(index).native_identity()),
                ),
            )
        })
        .collect();
    assert_eq!(
        refused,
        vec![
            (
                Err(breaks_rule(HASH_ROW, HASH_RULE)),
                Err(breaks_rule(530, IDENTITY_RULE))
            );
            keys.len()
        ]
    );
}

#[test]
fn an_owner_and_its_clone_share_one_hash_and_identity_so_each_further_claim_costs_one_row() {
    let owner = base();
    assert_eq!(
        (
            size::<HashedTwice>(),
            check_constraints(&HashedTwice {
                hash: hash_field(&owner),
                identity: identity_field(&owner),
                owner,
            }),
        ),
        (
            Size {
                constraints: HASH_SIZE.constraints + 2,
                variables: HASH_SIZE.variables + 1,
            },
            Ok(HASH_SIZE.constraints + 2),
        )
    );
}

#[test]
fn no_private_variable_of_the_owner_hash_fixture_is_free() {
    let keys = keys();
    assert_eq!(
        per_vector(&keys, |key| check_private_variables(&OwnerHash {
            hash: field_of(&key.native_hash()),
            owner: key.address,
        })),
        per_vector(&keys, |_| no_free_variable(771, 772))
    );
}

#[test]
fn the_tag_row_accepts_exactly_s_and_p_and_names_the_tag_rule() {
    let fixture = Instantiated { owner: base() };
    let honest = assignment(&fixture);
    let tag_wire = wire(&fixture, "an owner tag");
    let product = before_check(&fixture, TAG_RULE);
    let tag_row = check(&fixture, TAG_RULE).rows.start;
    let tags: Vec<u64> = (0..=255).collect();
    assert_eq!(
        (
            (tag_wire, product, tag_row),
            honest[product],
            tags.iter()
                .map(|tag| {
                    let tampered = with_wires(
                        honest.clone(),
                        &[(tag_wire, Fr::from(*tag)), (product, tag_product(*tag))],
                    );
                    first_unsatisfied::<Instantiated>(&tampered)
                })
                .collect::<Vec<_>>(),
        ),
        (
            (1, MINT_ROWS + 2, MINT_ROWS + 1),
            tag_product(u64::from(SOLANA_OWNER_TAG)),
            tags.iter()
                .map(|tag| {
                    (![u64::from(SOLANA_OWNER_TAG), u64::from(P256_OWNER_TAG)].contains(tag))
                        .then_some(tag_row)
                })
                .collect::<Vec<_>>(),
        )
    );
}

#[test]
fn the_tag_check_costs_an_unlabelled_product_row_and_one_rule_row() {
    let fixture = Instantiated { owner: base() };
    let tag = wire(&fixture, "an owner tag");
    let product = before_check(&fixture, TAG_RULE);
    let unlabelled = |row: usize| Err(("ProverError.ProofInputsBreakRule", Some(row), None));
    assert_eq!(
        (
            size::<Instantiated>(),
            check(&fixture, TAG_RULE).rows,
            check_tampered(&fixture, tag, Field::from(0x51u64)),
            check_tampered(&fixture, product, Field::from(1u64)),
        ),
        (
            Size {
                constraints: MINT_ROWS + 2,
                variables: MINT_ROWS + 4,
            },
            MINT_ROWS + 1..MINT_ROWS + 2,
            unlabelled(MINT_ROWS),
            unlabelled(MINT_ROWS),
        )
    );
}

#[test]
fn owner_equality_rows_refuse_every_single_field_change() {
    let cases = pair_cases();
    let key_rows = exported_first_unsatisfied::<KeyEqual>;
    let owner_rows = exported_first_unsatisfied::<OwnerEqual>;
    assert_eq!(
        (
            size::<KeyEqual>(),
            size::<OwnerEqual>(),
            size::<Pair>(),
            cases
                .iter()
                .map(|(name, left, right)| (
                    *name,
                    key_rows(*left, *right),
                    owner_rows(*left, *right)
                ))
                .collect::<Vec<_>>(),
        ),
        (
            Size {
                constraints: PAIR_ROWS + 2,
                variables: 583,
            },
            Size {
                constraints: PAIR_ROWS + 3,
                variables: 583,
            },
            Size {
                constraints: PAIR_ROWS,
                variables: 583,
            },
            vec![
                ("the same owner", None, None),
                ("the other tag", Some(PAIR_ROWS), Some(PAIR_ROWS)),
                ("key byte 0 flipped", Some(PAIR_ROWS), Some(PAIR_ROWS)),
                (
                    "key byte 31 flipped",
                    Some(PAIR_ROWS + 1),
                    Some(PAIR_ROWS + 1)
                ),
                ("nullifier key flipped", None, Some(PAIR_ROWS + 2)),
            ],
        )
    );
}

fn exported_first_unsatisfied<F: zk_program_sdk::ZkCircuit>(
    left: ClientOwner,
    right: ClientOwner,
) -> Option<usize> {
    first_unsatisfied::<F>(&assignment(&Pair { left, right }))
}

#[test]
fn a_flipped_equality_claim_breaks_exactly_the_claim_row() {
    let cases = pair_cases();
    let flipped = |left: ClientOwner, right: ClientOwner| {
        let key_claim = left.tag == right.tag && left.key == right.key;
        let key = KeyIsEqual {
            left,
            right,
            claimed: key_claim,
        };
        let owner = OwnerIsEqual {
            left,
            right,
            claimed: left == right,
        };
        (
            check_tampered(
                &key,
                wire(&key, "a bool proof input"),
                Field::from(u64::from(!key_claim)),
            ),
            check_tampered(
                &owner,
                wire(&owner, "a bool proof input"),
                Field::from(u64::from(left != right)),
            ),
        )
    };
    let (key_row, owner_row) = (
        size::<KeyIsEqual>().constraints - 1,
        size::<OwnerIsEqual>().constraints - 1,
    );
    assert_eq!(
        cases
            .iter()
            .map(|(_, left, right)| flipped(*left, *right))
            .collect::<Vec<_>>(),
        vec![
            (
                Err(breaks_rule(key_row, IS_EQUAL_RULE)),
                Err(breaks_rule(owner_row, IS_EQUAL_RULE))
            );
            cases.len()
        ]
    );
}

#[test]
fn assert_equal_if_refuses_a_changed_field_once_the_condition_is_set() {
    let cases: Vec<_> = pair_cases().into_iter().skip(1).collect();
    let set = |left: ClientOwner, right: ClientOwner| {
        let key = KeyEqualIf {
            left,
            right,
            condition: false,
        };
        let owner = OwnerEqualIf {
            left,
            right,
            condition: false,
        };
        (
            check_tampered(&key, wire(&key, "a bool proof input"), Field::from(1u64)),
            check_tampered(
                &owner,
                wire(&owner, "a bool proof input"),
                Field::from(1u64),
            ),
        )
    };
    assert_eq!(
        cases
            .iter()
            .map(|(name, left, right)| (*name, set(*left, *right)))
            .collect::<Vec<_>>(),
        vec![
            (
                "the other tag",
                (Err(equal_row(PAIR_ROWS + 1)), Err(equal_row(PAIR_ROWS + 1)))
            ),
            (
                "key byte 0 flipped",
                (Err(equal_row(PAIR_ROWS + 1)), Err(equal_row(PAIR_ROWS + 1)))
            ),
            (
                "key byte 31 flipped",
                (Err(equal_row(PAIR_ROWS + 2)), Err(equal_row(PAIR_ROWS + 2)))
            ),
            (
                "nullifier key flipped",
                (Ok(()), Err(equal_row(PAIR_ROWS + 3)))
            ),
        ]
    );
}

#[test]
fn select_rows_hold_for_both_conditions_and_a_flipped_condition_breaks_one() {
    let cases: Vec<_> = pair_cases().into_iter().skip(1).collect();
    let flipped = |left: ClientOwner, right: ClientOwner| {
        [true, false].map(|condition| {
            let chosen = if condition { left } else { right };
            let key = KeySelected {
                identity: identity_field(&chosen),
                condition,
                if_true: left,
                if_false: right,
            };
            let owner = OwnerSelected {
                hash: hash_field(&chosen),
                condition,
                if_true: left,
                if_false: right,
            };
            let key_condition = wire(&key, "a bool proof input");
            let owner_condition = wire(&owner, "a bool proof input");
            (
                check_constraints(&key),
                check_constraints(&owner),
                first_unsatisfied::<KeySelected>(&with_wires(
                    assignment(&key),
                    &[(key_condition, Fr::from(u64::from(!condition)))],
                )),
                first_unsatisfied::<OwnerSelected>(&with_wires(
                    assignment(&owner),
                    &[(owner_condition, Fr::from(u64::from(!condition)))],
                )),
            )
        })
    };
    assert_eq!(
        (
            size::<KeySelected>(),
            size::<OwnerSelected>(),
            cases
                .iter()
                .map(|(name, left, right)| (*name, flipped(*left, *right)))
                .collect::<Vec<_>>(),
        ),
        (
            Size {
                constraints: 855,
                variables: 858,
            },
            Size {
                constraints: 1096,
                variables: 1099,
            },
            vec![
                (
                    "the other tag",
                    [select_rows(Some(PAIR_ROWS + 1), Some(PAIR_ROWS + 1)); 2]
                ),
                (
                    "key byte 0 flipped",
                    [select_rows(Some(PAIR_ROWS + 2), Some(PAIR_ROWS + 2)); 2]
                ),
                (
                    "key byte 31 flipped",
                    [select_rows(Some(PAIR_ROWS + 33), Some(PAIR_ROWS + 33)); 2]
                ),
                (
                    "nullifier key flipped",
                    [select_rows(None, Some(PAIR_ROWS + 34)); 2]
                ),
            ],
        )
    );
}

type SelectRows = (
    Result<usize, crate::harness::fixture::ProverRefusal>,
    Result<usize, crate::harness::fixture::ProverRefusal>,
    Option<usize>,
    Option<usize>,
);

fn select_rows(key: Option<usize>, owner: Option<usize>) -> SelectRows {
    (Ok(855), Ok(1096), key, owner)
}

fn equal_row(row: usize) -> crate::harness::fixture::ProverRefusal {
    breaks_rule(row, EQUAL_RULE)
}
