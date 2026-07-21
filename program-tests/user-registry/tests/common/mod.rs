use solana_keypair::Keypair;
use solana_signer::Signer;
use user_registry_tests::{build_register_ix, test_p256_pubkey, UserRegistryTestRig};

pub const OWNER_LAMPORTS: u64 = 5_000_000_000;

#[derive(Clone, Copy)]
pub struct Keys {
    pub owner_p256: [u8; 33],
    pub nullifier: [u8; 32],
    pub viewing: [u8; 33],
}

pub fn keys(tag: u8) -> Keys {
    let mut nullifier = [0u8; 32];
    *nullifier.last_mut().expect("nullifier byte") = tag;
    Keys {
        owner_p256: test_p256_pubkey(tag),
        nullifier,
        viewing: test_p256_pubkey(tag.wrapping_add(0x40)),
    }
}

pub fn funded_keypair(rig: &mut UserRegistryTestRig) -> Keypair {
    let keypair = Keypair::new();
    rig.fund(&keypair.pubkey(), OWNER_LAMPORTS);
    keypair
}

pub fn register(rig: &mut UserRegistryTestRig, owner: &Keypair, value: Keys) {
    rig.send(
        build_register_ix(
            &owner.pubkey(),
            Some(value.owner_p256),
            value.nullifier,
            value.viewing,
        ),
        &[owner],
    )
    .expect("register user");
}
