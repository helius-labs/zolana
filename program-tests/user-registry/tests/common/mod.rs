// Each integration test compiles its own copy of these fixture helpers.
#![allow(dead_code)]

use solana_keypair::Keypair;
use solana_signer::Signer;
use spr_keypair::X25519Keypair;
use user_registry_tests::{build_register_ix, UserRegistryTestRig};

pub const OWNER_LAMPORTS: u64 = 5_000_000_000;

#[derive(Clone, Copy)]
pub struct Keys {
    pub nullifier: [u8; 32],
    pub viewing: [u8; 33],
}

pub fn keys(tag: u8) -> Keys {
    let mut nullifier = [0u8; 32];
    *nullifier.last_mut().expect("nullifier byte") = tag;
    Keys {
        nullifier,
        viewing: *X25519Keypair::from_bytes(&[tag; 32]).pubkey().as_bytes(),
    }
}

pub fn funded_keypair(rig: &mut UserRegistryTestRig) -> Keypair {
    let keypair = Keypair::new();
    rig.fund(&keypair.pubkey(), OWNER_LAMPORTS);
    keypair
}

pub fn register(rig: &mut UserRegistryTestRig, owner: &Keypair, value: Keys) {
    rig.send(
        build_register_ix(&owner.pubkey(), value.nullifier, value.viewing),
        &[owner],
    )
    .expect("register user");
}
