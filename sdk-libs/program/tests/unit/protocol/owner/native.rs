use solana_address::Address;
use zolana_hasher::primitives::{
    p256_owner_identity, solana_owner_identity, P256_OWNER_TAG, SOLANA_OWNER_TAG,
};
use zolana_keypair::{Curve, PublicKey, ShieldedAddress};
use zolana_program::{
    circuit::{value, DataHash, Field, Owner},
    conversion::{Allocator, FromCircuit, Placeholder, ProofInput},
    CircuitError, Owner as ClientOwner,
};

use super::{
    fixtures::{
        Identity, KeyEqual, KeyEqualIf, KeyIsEqual, KeySelected, OwnerDataHash, OwnerEqual,
        OwnerEqualIf, OwnerHash, OwnerIsEqual, OwnerSelected, PreimageHash, EQUAL_BROKEN,
        HASH_BROKEN, IDENTITY_BROKEN, IS_EQUAL_BROKEN,
    },
    keys,
    vectors::{
        hash_field, identity_field, identity_of, keys, neighbours, nullifier_pk, preimage, TAGS,
    },
};
use crate::{
    harness::{
        field::{be_bytes, MODULUS},
        fixture::{check_constraints, native, per_vector, rule_broken, Refusal},
    },
    protocol::asset::vectors::field_of,
};

pub const TAG_RULE: &str = "the owner tag is neither S nor P";
pub const TAG_FILE: &str = "sdk-libs/program/src/conversion/owner.rs";
pub const TAG_BROKEN: Refusal = rule_broken(TAG_RULE, TAG_FILE);

fn circuit(owner: &impl ProofInput<Circuit = Owner>) -> Owner {
    owner
        .instantiate(&Allocator::native())
        .expect("native owner")
}

fn constant(var: &zolana_program::circuit::CircuitVar) -> Field {
    value(var).expect("constant")
}

fn base() -> ClientOwner {
    preimage(SOLANA_OWNER_TAG, [3u8; 32], nullifier_pk(4))
}

#[test]
fn every_key_hashes_to_the_native_owner_hash_for_every_curve() {
    let keys = keys();
    assert_eq!(
        per_vector(&keys, |key| {
            let owner = circuit(&key.address);
            (
                constant(&owner.hash().expect("owner hash")),
                constant(&owner.key().identity().expect("identity")),
            )
        }),
        per_vector(&keys, |key| (
            field_of(&key.native_hash()),
            field_of(&key.native_identity())
        ))
    );
}

#[test]
fn the_identity_is_hash_bytes_of_the_tag_then_the_key() {
    let keys = keys();
    assert_eq!(
        per_vector(&keys, |key| {
            let preimage = key.preimage();
            (
                key.native_identity(),
                match key.address.signing_pubkey.curve().expect("curve") {
                    Curve::P256 => p256_owner_identity(&preimage.key),
                    Curve::Ed25519 | Curve::Pda => solana_owner_identity(&preimage.key),
                }
                .expect("tagged identity"),
            )
        }),
        per_vector(&keys, |key| {
            let identity = identity_of(&key.preimage());
            (identity, identity)
        })
    );
}

#[test]
fn the_key_tag_and_nullifier_key_accessors_read_the_preimage() {
    let keys = keys();
    assert_eq!(
        per_vector(&keys, |key| {
            let owner = circuit(&key.address);
            (
                constant(owner.key().tag()),
                constant(owner.nullifier_pk()),
                ClientOwner::from_circuit(&owner).map_err(|error| error.name()),
            )
        }),
        per_vector(&keys, |key| (
            Field::from(u64::from(if key.name == "p256" {
                P256_OWNER_TAG
            } else {
                SOLANA_OWNER_TAG
            })),
            field_of(&key.address.nullifier_pubkey),
            Ok(key.preimage()),
        ))
    );
}

#[test]
fn every_key_holds_natively_with_its_native_hash_and_identity() {
    let keys = keys();
    assert_eq!(
        per_vector(&keys, |key| [
            native(&OwnerHash {
                hash: field_of(&key.native_hash()),
                owner: key.address,
            }),
            native(&Identity {
                identity: field_of(&key.native_identity()),
                owner: key.address,
            }),
            native(&PreimageHash {
                hash: field_of(&key.native_hash()),
                owner: key.preimage(),
            }),
            native(&OwnerDataHash {
                hash: field_of(&key.native_hash()),
                owner: key.preimage(),
            }),
        ]),
        per_vector(&keys, |_| [Ok(()), Ok(()), Ok(()), Ok(())])
    );
}

#[test]
fn a_hash_or_identity_of_another_key_breaks_exactly_the_fixture_rule() {
    let keys = keys();
    let other = |index: usize| &keys[(index + 1) % keys.len()];
    let refused: Vec<_> = keys
        .iter()
        .enumerate()
        .map(|(index, key)| {
            (
                key.name,
                native(&OwnerHash {
                    hash: field_of(&other(index).native_hash()),
                    owner: key.address,
                }),
                native(&Identity {
                    identity: field_of(&other(index).native_identity()),
                    owner: key.address,
                }),
            )
        })
        .collect();
    assert_eq!(
        refused,
        keys.iter()
            .map(|key| (key.name, Err(HASH_BROKEN), Err(IDENTITY_BROKEN)))
            .collect::<Vec<_>>()
    );
}

#[test]
fn every_single_preimage_field_change_moves_the_hash_to_the_native_hash_of_the_change() {
    let base = base();
    let base_hash = constant(&circuit(&base).hash().expect("owner hash"));
    assert_eq!(
        neighbours(&base).map(|(name, neighbour)| {
            let hash = constant(&circuit(&neighbour).hash().expect("owner hash"));
            (name, hash, hash == base_hash)
        }),
        neighbours(&base).map(|(name, neighbour)| (name, hash_field(&neighbour), false))
    );
}

#[test]
fn an_ed25519_key_and_a_pda_with_the_same_bytes_share_the_identity_and_differ_from_p256() {
    let ed25519 = keys::ed25519(7);
    let key_bytes = ed25519.preimage().key;
    let pda = keys::pda_at(Address::new_from_array(key_bytes), 7);
    let p256_tagged = preimage(P256_OWNER_TAG, key_bytes, ed25519.address.nullifier_pubkey);
    let identity =
        |owner: &ClientOwner| constant(&circuit(owner).key().identity().expect("identity"));
    assert_eq!(
        (
            identity(&ed25519.preimage()),
            identity(&pda.preimage()),
            identity(&p256_tagged) == identity(&ed25519.preimage()),
            pda.native_identity() == ed25519.native_identity(),
        ),
        (
            identity_field(&ed25519.preimage()),
            identity_field(&ed25519.preimage()),
            false,
            true,
        )
    );
}

#[test]
fn every_tag_other_than_s_and_p_is_refused_by_exactly_the_tag_rule() {
    let tags: Vec<u8> = (0..=u8::MAX).collect();
    let refused: Vec<_> = tags
        .iter()
        .map(|tag| {
            let owner = preimage(*tag, [3u8; 32], nullifier_pk(4));
            (
                *tag,
                native(&PreimageHash {
                    hash: hash_field(&owner),
                    owner,
                }),
            )
        })
        .collect();
    assert_eq!(
        refused,
        tags.iter()
            .map(|tag| (
                *tag,
                if TAGS.contains(tag) {
                    Ok(())
                } else {
                    Err(TAG_BROKEN)
                }
            ))
            .collect::<Vec<_>>()
    );
}

#[test]
fn the_data_hash_of_an_owner_is_its_owner_hash() {
    let keys = keys();
    assert_eq!(
        per_vector(&keys, |key| {
            let owner = circuit(&key.address);
            constant(&DataHash::hash(&owner).expect("data hash"))
        }),
        per_vector(&keys, |key| field_of(&key.native_hash()))
    );
}

#[test]
fn the_placeholders_are_a_solana_tagged_owner() {
    let address = ShieldedAddress::placeholder().expect("placeholder address");
    let owner = ClientOwner::placeholder().expect("placeholder owner");
    assert_eq!(
        (
            address.signing_pubkey.curve().expect("curve"),
            owner,
            native(&PreimageHash {
                hash: hash_field(&owner),
                owner,
            }),
        ),
        (
            Curve::Ed25519,
            preimage(SOLANA_OWNER_TAG, [0u8; 32], [0u8; 32]),
            Ok(())
        )
    );
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
fn key_equality_ignores_the_nullifier_key_and_owner_equality_does_not() {
    let cases = pair_cases();
    let checks = |left: ClientOwner, right: ClientOwner| {
        (
            native(&KeyEqual { left, right }),
            native(&OwnerEqual { left, right }),
        )
    };
    assert_eq!(
        cases
            .iter()
            .map(|(name, left, right)| (*name, checks(*left, *right)))
            .collect::<Vec<_>>(),
        vec![
            ("the same owner", (Ok(()), Ok(()))),
            ("the other tag", (Err(EQUAL_BROKEN), Err(EQUAL_BROKEN))),
            ("key byte 0 flipped", (Err(EQUAL_BROKEN), Err(EQUAL_BROKEN))),
            (
                "key byte 31 flipped",
                (Err(EQUAL_BROKEN), Err(EQUAL_BROKEN))
            ),
            ("nullifier key flipped", (Ok(()), Err(EQUAL_BROKEN))),
        ]
    );
}

#[test]
fn is_equal_claims_hold_exactly_for_equal_keys_and_owners() {
    let cases = pair_cases();
    let claims = |left: ClientOwner, right: ClientOwner| -> [Result<(), Refusal>; 4] {
        [
            native(&KeyIsEqual {
                left,
                right,
                claimed: true,
            }),
            native(&KeyIsEqual {
                left,
                right,
                claimed: false,
            }),
            native(&OwnerIsEqual {
                left,
                right,
                claimed: true,
            }),
            native(&OwnerIsEqual {
                left,
                right,
                claimed: false,
            }),
        ]
    };
    let (holds, broken) = (Ok(()), Err(IS_EQUAL_BROKEN));
    assert_eq!(
        cases
            .iter()
            .map(|(name, left, right)| (*name, claims(*left, *right)))
            .collect::<Vec<_>>(),
        vec![
            ("the same owner", [holds, broken, holds, broken]),
            ("the other tag", [broken, holds, broken, holds]),
            ("key byte 0 flipped", [broken, holds, broken, holds]),
            ("key byte 31 flipped", [broken, holds, broken, holds]),
            ("nullifier key flipped", [holds, broken, broken, holds]),
        ]
    );
}

#[test]
fn assert_equal_if_checks_exactly_when_the_condition_holds() {
    let cases = pair_cases();
    let conditioned = |left: ClientOwner, right: ClientOwner, condition: bool| {
        (
            native(&KeyEqualIf {
                left,
                right,
                condition,
            }),
            native(&OwnerEqualIf {
                left,
                right,
                condition,
            }),
        )
    };
    assert_eq!(
        cases
            .iter()
            .map(|(name, left, right)| (
                *name,
                conditioned(*left, *right, true),
                conditioned(*left, *right, false)
            ))
            .collect::<Vec<_>>(),
        cases
            .iter()
            .map(|(name, left, right)| {
                let expected = |same: bool| if same { Ok(()) } else { Err(EQUAL_BROKEN) };
                (
                    *name,
                    (
                        expected(left.tag == right.tag && left.key == right.key),
                        expected(left == right),
                    ),
                    (Ok(()), Ok(())),
                )
            })
            .collect::<Vec<_>>()
    );
}

#[test]
fn select_takes_every_field_of_the_chosen_owner() {
    let cases = pair_cases();
    let selected = |condition: bool, left: ClientOwner, right: ClientOwner| {
        let chosen = if condition { left } else { right };
        (
            native(&KeySelected {
                identity: identity_field(&chosen),
                condition,
                if_true: left,
                if_false: right,
            }),
            native(&OwnerSelected {
                hash: hash_field(&chosen),
                condition,
                if_true: left,
                if_false: right,
            }),
        )
    };
    assert_eq!(
        cases
            .iter()
            .flat_map(|(_, left, right)| [
                selected(true, *left, *right),
                selected(false, *left, *right),
                selected(true, *right, *left),
                selected(false, *right, *left),
            ])
            .collect::<Vec<_>>(),
        vec![(Ok(()), Ok(())); 4 * cases.len()]
    );
}

#[test]
fn select_is_not_the_other_owner() {
    let base = base();
    let [(_, other_tag), _, _, (_, other_nullifier)] = neighbours(&base);
    assert_eq!(
        (
            native(&KeySelected {
                identity: identity_field(&other_tag),
                condition: true,
                if_true: base,
                if_false: other_tag,
            }),
            native(&OwnerSelected {
                hash: hash_field(&other_nullifier),
                condition: false,
                if_true: other_nullifier,
                if_false: base,
            }),
        ),
        (Err(IDENTITY_BROKEN), Err(HASH_BROKEN))
    );
}

fn refusal(error: CircuitError) -> (&'static str, String) {
    (error.name(), error.to_string())
}

#[test]
fn an_address_the_native_owner_hash_refuses_is_refused_as_an_invalid_owner() {
    let key = keys::ed25519(7);
    let refused = [
        ShieldedAddress {
            signing_pubkey: PublicKey::zeroed(),
            ..key.address
        },
        ShieldedAddress {
            nullifier_pubkey: [255u8; 32],
            ..key.address
        },
    ]
    .map(|address| {
        (
            address
                .owner_hash()
                .map(|_| ())
                .map_err(|error| error.to_string()),
            address
                .instantiate(&Allocator::native())
                .map(|_| ())
                .map_err(refusal),
            check_constraints(&OwnerHash {
                hash: Field::from(0u64),
                owner: address,
            }),
        )
    });
    assert_eq!(
        refused,
        [
            (
                Err("invalid public key".to_string()),
                Err((
                    "CircuitError.InvalidOwner",
                    "invalid proof input: invalid public key".to_string()
                )),
                Err(("CircuitError.InvalidOwner", None, None)),
            ),
            (
                Err("poseidon hash failed (code 8002)".to_string()),
                Err((
                    "CircuitError.InvalidOwner",
                    "invalid proof input: poseidon hash failed (code 8002)".to_string()
                )),
                Err(("CircuitError.InvalidOwner", None, None)),
            ),
        ]
    );
}

#[test]
fn a_nullifier_key_of_at_least_p_is_refused_before_it_reaches_the_circuit() {
    let refused: Vec<_> = [be_bytes(MODULUS), [255u8; 32]]
        .into_iter()
        .map(|nullifier_pk| {
            let owner = preimage(SOLANA_OWNER_TAG, [3u8; 32], nullifier_pk);
            (
                owner
                    .instantiate(&Allocator::native())
                    .map(|_| ())
                    .map_err(refusal),
                check_constraints(&PreimageHash {
                    hash: Field::from(0u64),
                    owner,
                }),
            )
        })
        .collect();
    assert_eq!(
        refused,
        vec![
            (
                Err((
                    "CircuitError.BytesTooLarge",
                    "32-byte input is too large for a circuit value".to_string()
                )),
                Err(("CircuitError.BytesTooLarge", None, None)),
            );
            2
        ]
    );
}
