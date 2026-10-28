#![allow(dead_code)]

#[path = "../../../../sdk-libs/transaction/tests/transfer_fixtures/mod.rs"]
mod transfer_fixtures;

use spr_keypair::ShieldedKeypair;
use spr_test_utils::wallet::{KeypairWalletAuthority, Wallet};
use spr_transaction::{Address, AssetRegistry};
pub use transfer_fixtures::*;

pub fn local_authority(keypair: &ShieldedKeypair) -> KeypairWalletAuthority<'_> {
    KeypairWalletAuthority::new(Address::default(), keypair)
}

pub fn wallet_for(keypair: &ShieldedKeypair, registry: AssetRegistry) -> Wallet {
    Wallet::new(keypair.shielded_address().unwrap(), registry).unwrap()
}
