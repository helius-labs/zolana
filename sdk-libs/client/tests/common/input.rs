use solana_signature::Signature;
use zolana_keypair::NullifierKey;
use zolana_transaction::{Utxo, WalletUtxo};

pub fn wallet_utxo(
    utxo: Utxo,
    key: &NullifierKey,
    tree_id: u16,
    leaf_index: u64,
    data_hash: Option<[u8; 32]>,
    ring_data_hash: Option<[u8; 32]>,
) -> WalletUtxo {
    let nullifier_pubkey = key.pubkey().expect("nullifier public key");
    let utxo_hash = utxo
        .hash(
            &nullifier_pubkey,
            &data_hash.unwrap_or_default(),
            &ring_data_hash.unwrap_or_default(),
            tree_id,
        )
        .expect("commitment");
    let nullifier = key
        .nullifier(&utxo_hash, &utxo.blinding)
        .expect("nullifier");
    WalletUtxo {
        utxo,
        nullifier_pubkey,
        utxo_hash,
        nullifier,
        data_hash,
        ring_data_hash,
        tree_id,
        leaf_index,
        slot: 0,
        tx_signature: Signature::default(),
        slot_index: 0,
    }
}
