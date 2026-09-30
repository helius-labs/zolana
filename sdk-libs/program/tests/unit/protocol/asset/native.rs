use solana_address::Address;
use zolana_hasher::primitives::hash_bytes;
use zolana_program::{
    circuit::{value, Asset, DataHash, Field},
    conversion::{Allocator, Placeholder, ProofInput},
};
use zolana_transaction::{Mint, SOL_MINT};

use super::{
    fixtures::{
        AssetDataHash, AssetHash, Equal, EqualIf, EqualsConstant, IsEqual, NotEqual, Selected,
        CONSTANT_MINT, EQUAL_BROKEN, HASH_BROKEN, IS_EQUAL_BROKEN,
    },
    vectors::{distinct_pairs, field_of, Vector, MINTS},
};
use crate::harness::fixture::{native, per_vector, Refusal};

fn hash_of(asset: &Asset) -> Field {
    value(&asset.hash().expect("asset hash")).expect("constant asset hash")
}

fn instantiated(mint: &Mint) -> Asset {
    mint.instantiate(&Allocator::native())
        .expect("native asset")
}

#[test]
fn every_mint_hashes_to_the_native_hash_bytes_of_its_32_bytes() {
    assert_eq!(
        per_vector(&MINTS, |vector| (
            hash_of(&instantiated(&vector.mint)),
            hash_of(&Asset::constant(&vector.mint.asset)),
            value(&DataHash::hash(&instantiated(&vector.mint)).expect("data hash"))
                .expect("constant data hash"),
        )),
        per_vector(&MINTS, |vector| {
            let native = field_of(&hash_bytes(vector.mint.asset.as_array()).expect("hash_bytes"));
            (native, native, native)
        })
    );
}

#[test]
fn every_mint_holds_natively_with_its_native_hash() {
    assert_eq!(
        per_vector(&MINTS, |vector| (
            native(&AssetHash {
                hash: vector.hash(),
                mint: vector.mint,
            }),
            native(&AssetDataHash {
                hash: vector.hash(),
                mint: vector.mint,
            }),
        )),
        per_vector(&MINTS, |_| (Ok(()), Ok(())))
    );
}

#[test]
fn a_claimed_hash_of_another_mint_breaks_exactly_the_hash_rule_natively() {
    let pairs = distinct_pairs();
    let refused: Vec<_> = pairs
        .iter()
        .flat_map(|(left, right)| {
            [
                native(&AssetHash {
                    hash: right.hash(),
                    mint: left.mint,
                }),
                native(&AssetHash {
                    hash: left.hash(),
                    mint: right.mint,
                }),
            ]
        })
        .collect();
    assert_eq!(refused, vec![Err(HASH_BROKEN); 2 * pairs.len()]);
}

#[test]
fn distinct_mints_have_distinct_hashes() {
    let hashes: Vec<Field> = MINTS
        .iter()
        .map(|vector| hash_of(&instantiated(&vector.mint)))
        .collect();
    let distinct: Vec<bool> = distinct_pairs()
        .iter()
        .map(|(left, right)| left.hash() != right.hash())
        .collect();
    assert_eq!(
        (hashes, distinct),
        (MINTS.iter().map(Vector::hash).collect(), vec![true; 15])
    );
}

#[test]
fn sol_is_the_all_zero_sol_mint_and_the_default_and_placeholder_asset() {
    let sol = field_of(&hash_bytes(&[0u8; 32]).expect("hash_bytes"));
    assert_eq!(
        (
            SOL_MINT,
            Mint::SOL.asset,
            Mint::placeholder().map_err(|error| error.name()),
            hash_of(&Asset::sol()),
            hash_of(&Asset::default()),
            hash_of(&Asset::constant(&SOL_MINT)),
            sol == Field::from(0u64),
        ),
        (
            Address::new_from_array([0u8; 32]),
            SOL_MINT,
            Ok(Mint::SOL),
            sol,
            sol,
            sol,
            false,
        )
    );
}

#[test]
fn assert_equal_holds_exactly_for_equal_mints_natively() {
    let pairs = distinct_pairs();
    assert_eq!(
        (
            per_vector(&MINTS, |vector| native(&Equal {
                left: vector.mint,
                right: vector.mint,
            })),
            pairs
                .iter()
                .map(|(left, right)| native(&Equal {
                    left: left.mint,
                    right: right.mint,
                }))
                .collect::<Vec<_>>(),
        ),
        (
            per_vector(&MINTS, |_| Ok(())),
            vec![Err(EQUAL_BROKEN); pairs.len()]
        )
    );
}

#[test]
fn assert_not_equal_holds_exactly_for_distinct_mints_natively() {
    let pairs = distinct_pairs();
    assert_eq!(
        (
            per_vector(&MINTS, |vector| native(&NotEqual {
                left: vector.mint,
                right: vector.mint,
            })),
            pairs
                .iter()
                .map(|(left, right)| native(&NotEqual {
                    left: left.mint,
                    right: right.mint,
                }))
                .collect::<Vec<_>>(),
        ),
        (
            per_vector(&MINTS, |_| Err(EQUAL_BROKEN)),
            vec![Ok(()); pairs.len()]
        )
    );
}

#[test]
fn is_equal_is_true_exactly_for_equal_mints_natively() {
    let claims = |left: Mint, right: Mint| -> [Result<(), Refusal>; 2] {
        [true, false].map(|claimed| {
            native(&IsEqual {
                left,
                right,
                claimed,
            })
        })
    };
    let pairs = distinct_pairs();
    assert_eq!(
        (
            per_vector(&MINTS, |vector| claims(vector.mint, vector.mint)),
            pairs
                .iter()
                .map(|(left, right)| claims(left.mint, right.mint))
                .collect::<Vec<_>>(),
        ),
        (
            per_vector(&MINTS, |_| [Ok(()), Err(IS_EQUAL_BROKEN)]),
            vec![[Err(IS_EQUAL_BROKEN), Ok(())]; pairs.len()]
        )
    );
}

#[test]
fn assert_equal_if_checks_exactly_when_the_condition_holds_natively() {
    let pairs = distinct_pairs();
    let conditioned = |left: Mint, right: Mint| -> [Result<(), Refusal>; 2] {
        [true, false].map(|condition| {
            native(&EqualIf {
                left,
                right,
                condition,
            })
        })
    };
    assert_eq!(
        (
            per_vector(&MINTS, |vector| conditioned(vector.mint, vector.mint)),
            pairs
                .iter()
                .map(|(left, right)| conditioned(left.mint, right.mint))
                .collect::<Vec<_>>(),
        ),
        (
            per_vector(&MINTS, |_| [Ok(()), Ok(())]),
            vec![[Err(EQUAL_BROKEN), Ok(())]; pairs.len()]
        )
    );
}

#[test]
fn a_constant_asset_equals_exactly_its_own_mint_natively() {
    assert_eq!(
        per_vector(&MINTS, |vector| native(&EqualsConstant {
            mint: vector.mint
        })),
        per_vector(&MINTS, |vector| if vector.mint == CONSTANT_MINT {
            Ok(())
        } else {
            Err(EQUAL_BROKEN)
        })
    );
}

#[test]
fn select_hashes_to_the_chosen_mint_natively() {
    let pairs = distinct_pairs();
    let selected = |condition: bool, (left, right): &(Vector, Vector), claimed: &Vector| {
        native(&Selected {
            hash: claimed.hash(),
            condition,
            if_true: left.mint,
            if_false: right.mint,
        })
    };
    assert_eq!(
        pairs
            .iter()
            .map(|pair| [
                selected(true, pair, &pair.0),
                selected(true, pair, &pair.1),
                selected(false, pair, &pair.1),
                selected(false, pair, &pair.0),
            ])
            .collect::<Vec<_>>(),
        vec![[Ok(()), Err(HASH_BROKEN), Ok(()), Err(HASH_BROKEN)]; pairs.len()]
    );
}
