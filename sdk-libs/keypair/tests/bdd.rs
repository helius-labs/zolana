mod steps;

use std::collections::HashMap;

use cucumber::World;
use zolana_keypair::{P256Pubkey, PublicKey, ShieldedKeypair, SigningKey, ViewingKey};

#[derive(Default, World)]
pub struct KeypairWorld {
    pub viewing: HashMap<String, ViewingKey>,
    pub shielded: HashMap<String, ShieldedKeypair>,
    pub signing: HashMap<String, SigningKey>,
    pub pubkeys: HashMap<String, P256Pubkey>,
    pub tagged: HashMap<String, PublicKey>,
    pub bytes: HashMap<String, Vec<u8>>,
    pub b32: HashMap<String, [u8; 32]>,
    pub sigs: HashMap<String, [u8; 64]>,
    pub last_error: bool,
    pub last_bool: bool,
}

impl std::fmt::Debug for KeypairWorld {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("KeypairWorld")
    }
}

impl KeypairWorld {
    pub fn vk(&self, name: &str) -> &ViewingKey {
        self.viewing.get(name).expect("viewing key not set")
    }

    pub fn keypair(&self, name: &str) -> &ShieldedKeypair {
        self.shielded.get(name).expect("shielded keypair not set")
    }

    pub fn sig_key(&self, name: &str) -> &SigningKey {
        self.signing.get(name).expect("signing key not set")
    }

    pub fn pubkey(&self, name: &str) -> P256Pubkey {
        *self.pubkeys.get(name).expect("p256 pubkey not set")
    }

    pub fn tag(&self, name: &str) -> PublicKey {
        *self.tagged.get(name).expect("tagged pubkey not set")
    }

    pub fn buf(&self, name: &str) -> Vec<u8> {
        self.bytes.get(name).expect("byte buffer not set").clone()
    }

    pub fn word(&self, name: &str) -> [u8; 32] {
        *self.b32.get(name).expect("32-byte value not set")
    }
}

pub fn scalar_bytes(n: u8) -> [u8; 32] {
    let mut s = [0u8; 32];
    s[31] = n;
    s
}

#[tokio::main]
async fn main() {
    KeypairWorld::cucumber()
        .fail_on_skipped()
        .run_and_exit("tests/features")
        .await;
}
