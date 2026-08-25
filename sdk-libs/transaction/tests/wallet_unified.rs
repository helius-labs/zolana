mod common;

use common::{
    build_unified_transfer, keypair_from_index, unique31, unique_nullifier, UnifiedTransferSpec,
};
#[cfg(feature = "parallel")]
use zolana_transaction::PrivateTransactionDirection;
use zolana_transaction::{Address, AssetRegistry, KeypairWalletAuthority, Wallet};

const WINDOW: u64 = 8;

#[test]
fn sync_stores_unified_change_and_recipient_utxos() {
    let assets = AssetRegistry::default();
    let alice = keypair_from_index(0);
    let bob = keypair_from_index(1);
    let mut counter = 0u64;

    let (tx, change_utxo, recipient_utxo) = build_unified_transfer(
        &assets,
        UnifiedTransferSpec {
            sender: &alice,
            recipient: &bob,
            amount: 40,
            change_amount: 60,
            first_nullifier: unique_nullifier(&mut counter),
            blinding: unique31(&mut counter, 0x01),
            change_blinding: unique31(&mut counter, 0x02),
        },
    );

    let alice_authority = KeypairWalletAuthority::new(Address::default(), &alice);
    let mut alice_wallet = Wallet::new(alice.shielded_address().unwrap(), assets.clone()).unwrap();
    alice_wallet
        .sync(&alice_authority, std::slice::from_ref(&tx), 1, WINDOW)
        .unwrap();
    assert_eq!(
        alice_wallet
            .utxos
            .iter()
            .map(|wallet_utxo| wallet_utxo.utxo.clone())
            .collect::<Vec<_>>(),
        vec![change_utxo]
    );

    let bob_authority = KeypairWalletAuthority::new(Address::default(), &bob);
    let mut bob_wallet = Wallet::new(bob.shielded_address().unwrap(), assets).unwrap();
    bob_wallet
        .sync(&bob_authority, std::slice::from_ref(&tx), 1, WINDOW)
        .unwrap();
    assert_eq!(
        bob_wallet
            .utxos
            .iter()
            .map(|wallet_utxo| wallet_utxo.utxo.clone())
            .collect::<Vec<_>>(),
        vec![recipient_utxo]
    );
}

/// The confidential rail through both scan strategies.
///
/// `sync_parallel` used to be a second copy of the scan that had silently lost
/// `record_confidential_send`, so it stored a confidential send's UTXOs but
/// recorded no outbound history for it. Both entry points now run one scan body.
///
/// Alice must own the spent input for a sender row to exist at all -- the row's
/// amount is spent-minus-change, and a row that nets to zero is dropped. So the
/// fixture funds her with a first transfer and reuses that UTXO's real nullifier
/// as the second transfer's first nullifier.
#[cfg(feature = "parallel")]
#[test]
fn parallel_scan_records_the_same_confidential_send_history() {
    let assets = AssetRegistry::default();
    let alice = keypair_from_index(2);
    let bob = keypair_from_index(3);
    let mut counter = 0u64;

    let (funding, _, _) = build_unified_transfer(
        &assets,
        UnifiedTransferSpec {
            sender: &bob,
            recipient: &alice,
            amount: 100,
            change_amount: 10,
            first_nullifier: unique_nullifier(&mut counter),
            blinding: unique31(&mut counter, 0x03),
            change_blinding: unique31(&mut counter, 0x04),
        },
    );
    let authority = KeypairWalletAuthority::new(Address::default(), &alice);

    let mut funded = Wallet::new(alice.shielded_address().unwrap(), assets.clone()).unwrap();
    funded
        .sync(&authority, std::slice::from_ref(&funding), 1, WINDOW)
        .unwrap();
    let spent_nullifier = funded
        .utxos
        .first()
        .expect("the funding transfer gave alice a UTXO")
        .nullifier;

    let (spend, _, _) = build_unified_transfer(
        &assets,
        UnifiedTransferSpec {
            sender: &alice,
            recipient: &bob,
            amount: 40,
            change_amount: 60,
            first_nullifier: spent_nullifier,
            blinding: unique31(&mut counter, 0x05),
            change_blinding: unique31(&mut counter, 0x06),
        },
    );
    let history = [funding, spend];

    let mut serial = Wallet::new(alice.shielded_address().unwrap(), assets.clone()).unwrap();
    serial.sync(&authority, &history, 1, WINDOW).unwrap();

    let mut parallel = Wallet::new(alice.shielded_address().unwrap(), assets).unwrap();
    parallel
        .sync_parallel(&authority, &history, 1, WINDOW)
        .unwrap();

    assert!(
        serial
            .private_transactions()
            .iter()
            .any(|row| row.direction == PrivateTransactionDirection::Outbound),
        "the fixture must produce a sender row for this test to mean anything; history={:?}",
        serial.private_transactions()
    );
    assert_eq!(
        parallel.private_transactions(),
        serial.private_transactions()
    );
    assert_eq!(
        parallel
            .utxos
            .iter()
            .map(|entry| entry.utxo.clone())
            .collect::<Vec<_>>(),
        serial
            .utxos
            .iter()
            .map(|entry| entry.utxo.clone())
            .collect::<Vec<_>>()
    );
}
