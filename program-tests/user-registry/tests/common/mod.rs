// Compiled separately into every test binary that includes it, and no single
// binary uses the whole surface (the P256 suite builds real keys instead of the
// `Keys` fixtures), so per-binary dead_code is expected here.
#![allow(dead_code)]

use solana_keypair::Keypair;
use solana_signer::Signer;
use user_registry_tests::{
    build_register_ixs, p256_binding_signature, p256_owner_pubkey, test_p256_pubkey, P256OwnerKey,
    UserRegistryTestRig,
};

pub const OWNER_LAMPORTS: u64 = 5_000_000_000;

#[derive(Clone, Copy)]
pub struct Keys {
    /// Seeds the fixture; kept so helpers can re-derive the P256 secret behind
    /// `owner_p256` (a `P256OwnerKey` is not `Copy`).
    pub tag: u8,
    pub owner_p256: [u8; 33],
    pub nullifier: [u8; 32],
    pub viewing: [u8; 33],
}

/// The P256 owner key behind `keys(tag)`. Deterministic so a fixture's public
/// key and its proof of possession can be derived independently; the scalar is
/// small by construction, which is fine for a test key and never leaves here.
pub fn signing_key(tag: u8) -> P256OwnerKey {
    let mut seed = [0u8; 32];
    seed[0] = 1;
    *seed.last_mut().expect("seed byte") = tag;
    P256OwnerKey::from_slice(&seed).expect("deterministic p256 test key")
}

pub fn keys(tag: u8) -> Keys {
    let mut nullifier = [0u8; 32];
    *nullifier.last_mut().expect("nullifier byte") = tag;
    Keys {
        tag,
        owner_p256: p256_owner_pubkey(&signing_key(tag)),
        nullifier,
        // Not proof-checked by the program, so a synthetic point is fine.
        viewing: test_p256_pubkey(tag.wrapping_add(0x40)),
    }
}

pub fn funded_keypair(rig: &mut UserRegistryTestRig) -> Keypair {
    let keypair = Keypair::new();
    rig.fund(&keypair.pubkey(), OWNER_LAMPORTS);
    keypair
}

/// Registers the record these suites mutate afterwards, with `value`'s P256
/// owner key and the proof of possession the program requires alongside it.
pub fn register(rig: &mut UserRegistryTestRig, owner: &Keypair, value: Keys) {
    let (owner_p256, signature) = p256_binding_signature(&owner.pubkey(), &signing_key(value.tag));
    assert_eq!(
        owner_p256, value.owner_p256,
        "fixture pubkey and its re-derived signing key must agree"
    );
    rig.send_all(
        &build_register_ixs(
            &owner.pubkey(),
            Some(owner_p256),
            value.nullifier,
            value.viewing,
            Some(signature),
        ),
        &[owner],
    )
    .expect("register user");
}
