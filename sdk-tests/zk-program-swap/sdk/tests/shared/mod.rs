use zolana_hasher::{primitives::hash_bytes, Hasher, Poseidon};
use zolana_keypair::{constants::BLINDING_LEN, NullifierKey};

pub fn order_utxo_owner_hash(order_authority: &[u8; 32]) -> [u8; 32] {
    let pk_field = hash_bytes(order_authority).expect("order authority field");
    let nullifier_pk = NullifierKey::from_secret([0u8; BLINDING_LEN])
        .pubkey()
        .expect("zero-secret nullifier pubkey");
    Poseidon::hashv(&[&pk_field, &nullifier_pk]).expect("order utxo owner hash")
}
