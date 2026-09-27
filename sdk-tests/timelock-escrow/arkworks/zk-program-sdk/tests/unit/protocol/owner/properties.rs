use ark_bn254::Fr;
use proptest::prelude::*;
use zk_program_sdk::Owner as ClientOwner;
use zolana_keypair::{ShieldedAddress, ShieldedKeypair, SigningKey};

use super::{
    fixtures::{OwnerHash, PreimageHash, CLAIM_WIRE, HASH_BROKEN},
    native::TAG_BROKEN,
    r1cs::HASH_ROW,
    vectors::{hash_field, preimage, TAGS},
};
use crate::{
    harness::fixture::{assignment, first_unsatisfied, native, with_wires},
    protocol::asset::vectors::field_of,
};

fn address(signing_key: SigningKey) -> ShieldedAddress {
    ShieldedKeypair::from_keypair(signing_key)
        .and_then(|keypair| keypair.shielded_address())
        .expect("address")
}

fn arbitrary_address() -> impl Strategy<Value = ShieldedAddress> {
    prop_oneof![
        any::<[u8; 32]>().prop_map(|seed| address(SigningKey::from_ed25519_bytes(&seed))),
        any::<[u8; 32]>().prop_filter_map("a p256 scalar", |seed| {
            SigningKey::from_p256_bytes(&seed).ok().map(address)
        }),
    ]
}

fn arbitrary_nullifier_pk() -> impl Strategy<Value = [u8; 32]> {
    any::<[u8; 32]>().prop_map(|mut bytes| {
        bytes[0] = 0;
        bytes
    })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(16))]

    #[test]
    fn every_random_key_hashes_to_its_native_owner_hash_natively_and_in_r1cs(
        address in arbitrary_address(),
    ) {
        let fixture = OwnerHash {
            hash: field_of(&address.owner_hash().expect("owner hash")),
            owner: address,
        };
        prop_assert_eq!(
            (native(&fixture), first_unsatisfied::<OwnerHash>(&assignment(&fixture))),
            (Ok(()), None)
        );
    }

    #[test]
    fn every_preimage_hashes_to_poseidon_of_its_identity_and_nullifier_key(
        tag in prop::sample::select(TAGS.to_vec()),
        key in any::<[u8; 32]>(),
        nullifier_pk in arbitrary_nullifier_pk(),
        other_nullifier_pk in arbitrary_nullifier_pk(),
    ) {
        prop_assume!(nullifier_pk != other_nullifier_pk);
        let owner = preimage(tag, key, nullifier_pk);
        let other = ClientOwner { nullifier_pk: other_nullifier_pk, ..owner };
        let fixture = PreimageHash { hash: hash_field(&owner), owner };
        let tampered = with_wires(assignment(&fixture), &[(CLAIM_WIRE, Fr::from(hash_field(&other)))]);
        prop_assert_eq!(
            (
                native(&fixture),
                native(&PreimageHash { hash: hash_field(&other), owner }),
                first_unsatisfied::<PreimageHash>(&tampered),
            ),
            (Ok(()), Err(HASH_BROKEN), Some(HASH_ROW))
        );
    }

    #[test]
    fn a_random_tag_is_accepted_exactly_when_it_is_s_or_p(
        tag in any::<u8>(),
        key in any::<[u8; 32]>(),
        nullifier_pk in arbitrary_nullifier_pk(),
    ) {
        let owner = preimage(tag, key, nullifier_pk);
        prop_assert_eq!(
            native(&PreimageHash { hash: hash_field(&owner), owner }),
            if TAGS.contains(&tag) { Ok(()) } else { Err(TAG_BROKEN) }
        );
    }
}
