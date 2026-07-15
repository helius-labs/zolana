mod common;

use common::{
    build_unified_transfer, keypair_from_index, unique31, unique_nullifier, UnifiedTransferSpec,
};
use zolana_transaction::{Address, AssetRegistry, LocalWalletAuthority, Wallet};

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

    let alice_authority = LocalWalletAuthority::new(Address::default(), &alice);
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

    let bob_authority = LocalWalletAuthority::new(Address::default(), &bob);
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
