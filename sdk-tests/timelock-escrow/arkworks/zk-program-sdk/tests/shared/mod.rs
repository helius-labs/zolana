use solana_signature::Signature;
use zolana_keypair::{random_blinding, ShieldedKeypair, SigningKey};
use zolana_transaction::{utxo::Utxo, Data, Mint, WalletUtxo};

pub const TREE_ID: u16 = 3;

pub fn keypair(seed: u8) -> ShieldedKeypair {
    ShieldedKeypair::from_keypair(SigningKey::from_ed25519_bytes(&[seed; 32])).expect("keypair")
}

pub fn spendable(owner: &ShieldedKeypair, mint: Mint, amount: u64, leaf_index: u64) -> WalletUtxo {
    let address = owner.shielded_address().expect("owner address");
    let utxo = Utxo {
        owner: owner.signing_pubkey(),
        asset: mint,
        amount,
        blinding: random_blinding(),
        ring_program_id: None,
        data: Data::default(),
    };
    let utxo_hash = utxo
        .hash(&address.nullifier_pubkey, &[0u8; 32], &[0u8; 32], TREE_ID)
        .expect("utxo hash");
    WalletUtxo {
        nullifier: owner
            .nullifier(&utxo_hash, &utxo.blinding)
            .expect("nullifier"),
        utxo,
        nullifier_pubkey: address.nullifier_pubkey,
        utxo_hash,
        data_hash: None,
        ring_data_hash: None,
        tree_id: TREE_ID,
        leaf_index,
        latest_tree_id: None,
        slot: 0,
        tx_signature: Signature::default(),
        slot_index: 0,
    }
}
