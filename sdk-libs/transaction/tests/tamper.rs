mod common;

use common::{build_transfer, keypair_from_index, local_authority, wallet_for, TransferSpec};
use zolana_keypair::constants::{P256_PUBKEY_LEN, PUBLIC_KEY_LEN};
use zolana_keypair::ShieldedKeypair;
use zolana_transaction::{
    Address, AssetRegistry, OutputContext, OutputSlot, ShieldedTransaction, Utxo, Wallet,
    DEFAULT_TAG_WINDOW,
};

const BORSH_HEADER_LEN: usize = 5;
const SCHEME_BYTE_LEN: usize = 1;
const ASSET_ID_LEN: usize = 8;
const AMOUNT_LEN: usize = 8;
const RECIPIENT_SLOT: usize = 1;
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
            blinding: {
                let mut b = [0u8; 32];
                b[1..].fill(0xBB);
                b
            },
            blinding_seed: [0xCC; 32],
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

/// A forged surplus slot appended after the real outputs (reusing the real
/// recipient's view tag) must not corrupt discovery: the tag-window scan
/// skips it and the real output is still recovered with the right amount.
/// Restores the base "extra recipient slot" scenario as a real forged-slot
/// test; spec.md leaves surplus-slot tolerance open (Q-COV-5), so this pins
/// the implemented behavior.
#[test]
fn forged_trailing_output_slot_is_ignored() {
    let (mut tx, recipient_utxo, _assets) = transfer_alice_receives();
    let forged_tag = tx
        .output_slots
        .get(RECIPIENT_SLOT)
        .expect("recipient slot")
        .view_tag;
    tx.output_slots.push(OutputSlot {
        view_tag: forged_tag,
        output_context: OutputContext {
            hash: [0xEE; 32],
            tree: Address::new_from_array([0u8; 32]),
            leaf_index: 9,
        },
        payload: vec![0xEE; 130],
    });

    let (keypair, mut wallet) = alice_wallet();
    wallet
        .sync(
            &local_authority(&keypair),
            std::slice::from_ref(&tx),
            1,
            DEFAULT_TAG_WINDOW,
        )
        .expect("sync tolerates the forged trailing slot");
    assert_eq!(wallet.utxos.len(), 1, "only the real output is discovered");
    let discovered = wallet.utxos.first().expect("real utxo");
    assert_eq!(discovered.utxo, recipient_utxo);
    assert_eq!(
        discovered.utxo.amount, 1_000,
        "the discovered balance is the real transfer amount"
    );
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
