//! Sync a wallet from the indexer and read its private balances.
//!
//! `sync_wallet` scans the indexer for the wallet's view tags, decrypts the
//! UTXOs it owns, and marks spent notes. `get_private_token_balances` and
//! `get_private_transactions` then read the synced state.

use anyhow::Result;
use rust_client_example::{new_party, setup, shield_sol};
use zolana_client::{get_private_token_balances, get_private_transactions, sync_wallet};

fn main() -> Result<()> {
    let mut context = setup()?;
    let (sender_keypair, _sender_funding, mut sender_wallet) = new_party(&mut context)?;

    shield_sol(&mut context, &sender_keypair, &mut sender_wallet, 5_000_000)?;
    shield_sol(&mut context, &sender_keypair, &mut sender_wallet, 2_000_000)?;

    let report = sync_wallet(&mut sender_wallet, &context.indexer)?;
    let balances = get_private_token_balances(&sender_wallet)?;
    let transactions = get_private_transactions(&sender_wallet);

    println!(
        "ok sync balances={balances:?} transactions={} report={report:?}",
        transactions.len()
    );
    Ok(())
}
