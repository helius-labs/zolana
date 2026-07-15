mod common;

use common::{build_transfer, keypair_from_index, local_authority, wallet_for, TransferSpec};
use zolana_keypair::constants::{BLINDING_LEN, P256_PUBKEY_LEN, PUBLIC_KEY_LEN};
use zolana_keypair::ShieldedKeypair;
use zolana_transaction::{AssetRegistry, ShieldedTransaction, Utxo, Wallet, DEFAULT_TAG_WINDOW};

const BORSH_HEADER_LEN: usize = 5;
const SCHEME_BYTE_LEN: usize = 1;
const ASSET_ID_LEN: usize = 8;
const AMOUNT_LEN: usize = 8;
const RECIPIENT_SLOT: usize = 2;
const AMOUNT_OFFSET: usize =
    BORSH_HEADER_LEN + SCHEME_BYTE_LEN + PUBLIC_KEY_LEN + P256_PUBKEY_LEN + ASSET_ID_LEN;

fn transfer_alice_receives() -> (ShieldedTransaction, Utxo, AssetRegistry) {
    let assets = AssetRegistry::default();
    let alice = keypair_from_index(0);
    let bob = keypair_from_index(1);
    let (tx, recipient_utxo, _change) = build_transfer(
        &assets,
        TransferSpec {
            sender: &bob,
            recipient: &alice,
            amount: 1_000,
            slot_tag: alice.recipient_bootstrap_view_tag(),
            sender_view_tag: bob.get_sender_view_tag(0).unwrap(),
            first_nullifier: [0xAB; 32],
            change_amount: 0,
            blinding: [0xBB; BLINDING_LEN],
            blinding_seed: [0xCC; BLINDING_LEN],
        },
    );
    (tx, recipient_utxo, assets)
}

fn alice_wallet() -> (ShieldedKeypair, Wallet) {
    let keypair = keypair_from_index(0);
    let wallet = wallet_for(&keypair, AssetRegistry::default());
    (keypair, wallet)
}

#[test]
fn untampered_transfer_is_discovered() {
    let (tx, recipient_utxo, _assets) = transfer_alice_receives();
    let (keypair, mut wallet) = alice_wallet();
    wallet
        .sync(
            &local_authority(&keypair),
            std::slice::from_ref(&tx),
            1,
            DEFAULT_TAG_WINDOW,
        )
        .unwrap();
    assert_eq!(wallet.utxos.len(), 1);
    assert_eq!(wallet.utxos.first().unwrap().utxo, recipient_utxo);
}

#[test]
fn tampered_ciphertext_is_rejected_by_utxo_hash() {
    let (mut tx, _recipient_utxo, _assets) = transfer_alice_receives();

    let recipient_payload = &mut tx
        .output_slots
        .get_mut(RECIPIENT_SLOT)
        .expect("recipient slot")
        .payload;
    let amount_bytes = recipient_payload
        .get_mut(AMOUNT_OFFSET..AMOUNT_OFFSET + AMOUNT_LEN)
        .expect("payload reaches the encrypted amount field");
    for byte in amount_bytes {
        *byte ^= 0xff;
    }

    let (keypair, mut wallet) = alice_wallet();
    let report = wallet
        .sync(
            &local_authority(&keypair),
            std::slice::from_ref(&tx),
            1,
            DEFAULT_TAG_WINDOW,
        )
        .unwrap();
    assert!(wallet.utxos.is_empty(), "{:?}", wallet.utxos);
    assert!(report.undecryptable_candidates >= 1);
}
