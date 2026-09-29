use zk_program_sdk::{circuit::Field, Owner as ClientOwner};
use zolana_hasher::{
    primitives::{hash_bytes, P256_OWNER_TAG, SOLANA_OWNER_TAG},
    Hasher, Poseidon,
};

use super::keys::{self, Key};
use crate::{harness::fixture::Named, protocol::asset::vectors::field_of};

pub const TAGS: [u8; 2] = [SOLANA_OWNER_TAG, P256_OWNER_TAG];

impl Named for Key {
    fn name(&self) -> &'static str {
        self.name
    }
}

impl Key {
    pub fn preimage(&self) -> ClientOwner {
        ClientOwner::try_from(&self.address).expect("owner preimage")
    }

    pub fn native_hash(&self) -> [u8; 32] {
        self.address.owner_hash().expect("native owner hash")
    }

    pub fn native_identity(&self) -> [u8; 32] {
        self.address
            .signing_pubkey
            .owner_proof_input_hash()
            .expect("native identity")
    }
}

pub fn keys() -> Vec<Key> {
    [7u8, 42].into_iter().flat_map(keys::every_curve).collect()
}

pub fn preimage(tag: u8, key: [u8; 32], nullifier_pk: [u8; 32]) -> ClientOwner {
    ClientOwner {
        tag,
        key,
        nullifier_pk,
    }
}

pub fn identity_of(owner: &ClientOwner) -> [u8; 32] {
    let mut tagged = [0u8; 33];
    tagged[0] = owner.tag;
    tagged[1..].copy_from_slice(&owner.key);
    hash_bytes(&tagged).expect("native identity")
}

pub fn hash_of(owner: &ClientOwner) -> [u8; 32] {
    Poseidon::hashv(&[&identity_of(owner), &owner.nullifier_pk]).expect("native owner hash")
}

pub fn identity_field(owner: &ClientOwner) -> Field {
    field_of(&identity_of(owner))
}

pub fn hash_field(owner: &ClientOwner) -> Field {
    field_of(&hash_of(owner))
}

pub fn nullifier_pk(seed: u8) -> [u8; 32] {
    let mut bytes = [seed; 32];
    bytes[0] = 0;
    bytes
}

/// Owner preimages that differ from `base` in exactly one of the tag, the
/// first key byte, the last key byte and the nullifier key.
pub fn neighbours(base: &ClientOwner) -> [(&'static str, ClientOwner); 4] {
    let other_tag = if base.tag == SOLANA_OWNER_TAG {
        P256_OWNER_TAG
    } else {
        SOLANA_OWNER_TAG
    };
    let mut first = base.key;
    first[0] ^= 1;
    let mut last = base.key;
    last[31] ^= 1;
    let mut nullifier_pk = base.nullifier_pk;
    nullifier_pk[31] ^= 1;
    [
        (
            "the other tag",
            ClientOwner {
                tag: other_tag,
                ..*base
            },
        ),
        (
            "key byte 0 flipped",
            ClientOwner {
                key: first,
                ..*base
            },
        ),
        ("key byte 31 flipped", ClientOwner { key: last, ..*base }),
        (
            "nullifier key flipped",
            ClientOwner {
                nullifier_pk,
                ..*base
            },
        ),
    ]
}
