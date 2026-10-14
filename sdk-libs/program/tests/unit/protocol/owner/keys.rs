use solana_address::Address;
use zolana_keypair::{
    NullifierKey, ShieldedAddress, ShieldedKeypair, ShieldedPda, SigningKey, ViewingKey,
};

#[derive(Clone)]
pub struct Key {
    pub name: &'static str,
    pub address: ShieldedAddress,
    pub nullifier_key: NullifierKey,
}

pub fn ed25519(seed: u8) -> Key {
    keypair("ed25519", SigningKey::from_ed25519_bytes(&[seed; 32]))
}

pub fn p256(seed: u8) -> Key {
    keypair(
        "p256",
        SigningKey::from_p256_bytes(&[seed; 32]).expect("p256 secret"),
    )
}

pub fn pda(seed: u8) -> Key {
    pda_at(Address::new_from_array([seed; 32]), seed)
}

pub fn pda_at(address: Address, seed: u8) -> Key {
    let viewing_key = ViewingKey::from_bytes(&[seed; 32]).expect("viewing secret");
    let pda =
        ShieldedPda::with_viewing_key(address, NullifierKey::from_secret([seed; 31]), viewing_key);
    Key {
        name: "pda",
        address: pda.shielded_address().expect("pda address"),
        nullifier_key: pda.as_ref().clone(),
    }
}

pub fn every_curve(seed: u8) -> [Key; 3] {
    [ed25519(seed), pda(seed), p256(seed)]
}

fn keypair(name: &'static str, signing_key: SigningKey) -> Key {
    let keypair = ShieldedKeypair::from_keypair(signing_key).expect("keypair");
    Key {
        name,
        address: keypair.shielded_address().expect("address"),
        nullifier_key: keypair.as_ref().clone(),
    }
}
