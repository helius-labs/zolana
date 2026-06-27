mod common;

use common::{build_transfer, keypair_from_index, unique31, unique_nullifier, TransferSpec};
use zolana_transaction::{
    AssetRegistry, PrivateTransactionDirection, PrivateTransactionKind, Wallet, SOL_MINT,
};

const WINDOW: u64 = 8;

#[test]
fn sync_records_inbound_and_outbound_transfer_history() {
    let assets = AssetRegistry::default();
    let alice = keypair_from_index(0);
    let bob = keypair_from_index(1);
    let mut counter = 0u64;

    let bootstrap_tag = alice.recipient_bootstrap_view_tag();
    let nullifier = unique_nullifier(&mut counter);
    let blinding = unique31(&mut counter, 0x01);
    let (bootstrap_tx, _, _) = build_transfer(
        &assets,
        TransferSpec {
            sender: &bob,
            recipient: &alice,
            amount: 100,
            slot_tag: bootstrap_tag,
            sender_view_tag: bob.get_sender_view_tag(0).unwrap(),
            first_nullifier: nullifier,
            change_amount: 0,
            blinding,
            blinding_seed: unique31(&mut counter, 0x02),
        },
    );

    let mut alice_wallet = Wallet::new(alice.clone()).unwrap();
    alice_wallet
        .sync(std::slice::from_ref(&bootstrap_tx), &assets, 1, WINDOW)
        .unwrap();
    assert_eq!(alice_wallet.private_transactions().len(), 1);
    let inbound = &alice_wallet.private_transactions()[0];
    assert_eq!(inbound.kind, PrivateTransactionKind::PrivateTransfer);
    assert_eq!(inbound.direction, PrivateTransactionDirection::Inbound);
    assert_eq!(inbound.amount, 100);
    assert_eq!(
        inbound.counterparty_viewing_pubkey,
        Some(bob.viewing_pubkey())
    );

    let spent_utxo = alice_wallet.utxos[0].utxo.clone();
    let spent_nullifier_pk = alice.nullifier_key.pubkey().unwrap();
    let spent_hash = spent_utxo
        .hash(&spent_nullifier_pk, &[0u8; 32], &[0u8; 32])
        .unwrap();
    let spend_nullifier = spent_utxo
        .nullifier(&spent_hash, &alice.nullifier_key)
        .unwrap();
    let shared_tag = alice
        .get_send_shared_view_tag(&bob.viewing_pubkey(), 0)
        .unwrap();
    let (outbound_tx, _, _) = build_transfer(
        &assets,
        TransferSpec {
            sender: &alice,
            recipient: &bob,
            amount: 40,
            slot_tag: shared_tag,
            sender_view_tag: alice.get_sender_view_tag(0).unwrap(),
            first_nullifier: spend_nullifier,
            change_amount: 60,
            blinding: unique31(&mut counter, 0x03),
            blinding_seed: unique31(&mut counter, 0x04),
        },
    );

    alice_wallet
        .sync(&[bootstrap_tx, outbound_tx], &assets, 2, WINDOW)
        .unwrap();
    assert_eq!(alice_wallet.private_transactions().len(), 2);

    let outbound = alice_wallet
        .private_transactions()
        .iter()
        .find(|tx| tx.direction == PrivateTransactionDirection::Outbound)
        .expect("outbound history row");
    assert_eq!(outbound.kind, PrivateTransactionKind::PrivateTransfer);
    assert_eq!(outbound.amount, 40);
    assert_eq!(outbound.asset, SOL_MINT);
    assert_eq!(
        outbound.counterparty_viewing_pubkey,
        Some(bob.viewing_pubkey())
    );
}

#[cfg(feature = "parallel")]
#[test]
fn sync_parallel_records_same_history_as_sync() {
    let assets = AssetRegistry::default();
    let alice = keypair_from_index(10);
    let bob = keypair_from_index(11);
    let mut counter = 0u64;

    let (tx, _, _) = build_transfer(
        &assets,
        TransferSpec {
            sender: &bob,
            recipient: &alice,
            amount: 55,
            slot_tag: alice.recipient_bootstrap_view_tag(),
            sender_view_tag: bob.get_sender_view_tag(0).unwrap(),
            first_nullifier: unique_nullifier(&mut counter),
            change_amount: 0,
            blinding: unique31(&mut counter, 0x11),
            blinding_seed: unique31(&mut counter, 0x12),
        },
    );

    let mut serial = Wallet::new(alice.clone()).unwrap();
    serial.sync(&[tx.clone()], &assets, 1, WINDOW).unwrap();

    let mut parallel = Wallet::new(alice).unwrap();
    parallel.sync_parallel(&[tx], &assets, 1, WINDOW).unwrap();

    assert_eq!(
        serial.private_transactions(),
        parallel.private_transactions()
    );
}
