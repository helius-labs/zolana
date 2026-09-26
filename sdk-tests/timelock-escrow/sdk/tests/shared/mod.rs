use zolana_hasher::primitives::solana_owner_identity;
use zolana_keypair::{constants::BLINDING_LEN, hash::poseidon, NullifierKey};

/// The escrow authority is a PDA, so its identity carries the Solana owner tag
/// like the program's owner derivation.
pub fn escrow_utxo_owner_hash(escrow_authority: &[u8; 32]) -> [u8; 32] {
    let pk_field = solana_owner_identity(escrow_authority).expect("escrow authority field");
    let nullifier_pk = NullifierKey::from_secret([0u8; BLINDING_LEN])
        .pubkey()
        .expect("zero-secret nullifier pubkey");
    poseidon(&[&pk_field, &nullifier_pk]).expect("escrow utxo owner hash")
}
