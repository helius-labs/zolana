use zolana_hasher::primitives::solana_owner_identity;
use zolana_keypair::{constants::BLINDING_LEN, hash::poseidon, NullifierKey};

/// The order authority is a PDA, so its identity carries the Solana owner tag
/// like the program's `PdaOwner` derivation.
pub fn order_utxo_owner_hash(order_authority: &[u8; 32]) -> [u8; 32] {
    let pk_field = solana_owner_identity(order_authority).expect("order authority field");
    let nullifier_pk = NullifierKey::from_secret([0u8; BLINDING_LEN])
        .pubkey()
        .expect("zero-secret nullifier pubkey");
    poseidon(&[&pk_field, &nullifier_pk]).expect("order utxo owner hash")
}
