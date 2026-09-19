use solana_signature::Signature;
use zolana_keypair::{ShieldedKeypair, SigningKey};
use zolana_transaction::{Data, Mint, Utxo, WalletUtxo};

pub fn keypair(seed: u8) -> ShieldedKeypair {
    ShieldedKeypair::from_keypair(SigningKey::from_ed25519_bytes(&[seed; 32]))
        .expect("fixture keypair")
}

/// A real note with consistent commitment/nullifier and distinctive metadata.
/// Tests mutate copies to isolate validation failures, or use independent
/// expected amounts and owners when asserting transaction results.
pub fn wallet_utxo(
    owner: &ShieldedKeypair,
    mint: Mint,
    amount: u64,
    tree_id: u16,
    nonce: u8,
) -> WalletUtxo {
    let mut blinding = [0; 32];
    blinding[31] = nonce;
    let utxo = Utxo {
        owner: owner.signing_pubkey(),
        asset: mint,
        amount,
        blinding,
        ring_program_id: None,
        data: Data::default(),
    };
    let nullifier_pubkey = owner
        .shielded_address()
        .expect("fixture address")
        .nullifier_pubkey;
    let utxo_hash = utxo
        .hash(&nullifier_pubkey, &[0; 32], &[0; 32], tree_id)
        .expect("fixture commitment");
    let nullifier = owner
        .nullifier(&utxo_hash, &blinding)
        .expect("fixture nullifier");
    WalletUtxo {
        utxo,
        nullifier_pubkey,
        utxo_hash,
        nullifier,
        data_hash: None,
        ring_data_hash: None,
        tree_id,
        leaf_index: u64::from(nonce),
        slot: u64::from(nonce),
        tx_signature: Signature::from([nonce; 64]),
        slot_index: 0,
    }
}
