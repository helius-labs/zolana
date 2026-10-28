mod wallet_common;

use spr_transaction::{AssetRegistry, TransactionError};
use wallet_common::{keypair_from_index, local_authority, wallet_for};

const WINDOW: u64 = 8;

#[test]
fn sync_rejects_an_authority_for_another_wallet() {
    let alice = keypair_from_index(0);
    let bob = keypair_from_index(1);
    let mut wallet = wallet_for(&alice, AssetRegistry::default());

    let error = wallet
        .sync(&local_authority(&bob), &[], 1, WINDOW)
        .expect_err("mismatched authority");

    assert_eq!(error, TransactionError::WalletAuthorityMismatch);
}
