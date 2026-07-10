mod balance;
mod deposit;
mod material;
mod registry;
mod resolve;
mod sync;
mod test_mint;
mod transaction;
mod tree;
mod util;
mod withdraw;

use std::time::Duration;

use anyhow::Result;

use crate::args::WalletCommand;

/// Default post-send indexer wait, overridable via `ZOLANA_INDEXER_TIMEOUT_SECS`.
/// A confirmed-but-unindexed transaction is still a success on timeout (see
/// [`sync::wait_for_indexed_output`]), so this bounds how long the CLI blocks
/// before reporting `mode=shielded (indexing pending)`.
const DEFAULT_INDEXER_TIMEOUT_SECS: u64 = 120;
const INDEXER_POLL: Duration = Duration::from_millis(500);

/// Resolve the indexer wait timeout from `ZOLANA_INDEXER_TIMEOUT_SECS` (seconds),
/// falling back to [`DEFAULT_INDEXER_TIMEOUT_SECS`] when unset or unparsable.
pub(crate) fn indexer_timeout() -> Duration {
    let secs = std::env::var("ZOLANA_INDEXER_TIMEOUT_SECS")
        .ok()
        .and_then(|value| value.trim().parse::<u64>().ok())
        .unwrap_or(DEFAULT_INDEXER_TIMEOUT_SECS);
    Duration::from_secs(secs)
}

pub(crate) fn run_wallet(command: WalletCommand) -> Result<()> {
    match command {
        WalletCommand::New(opts) => material::run_new(opts),
        WalletCommand::Address(opts) => material::run_address(opts),
        WalletCommand::Balance(opts) => balance::run_balance(opts),
        WalletCommand::SetMerging(opts) => registry::run_set_merging(opts),
        WalletCommand::Consolidate(opts) => transaction::run_consolidate(opts),
        WalletCommand::Deposit(opts) => deposit::run_deposit(opts),
        WalletCommand::Transfer(opts) => transaction::run_transfer(opts),
        WalletCommand::Withdraw(opts) => withdraw::run_withdraw(opts),
        WalletCommand::Split(opts) => transaction::run_split(opts),
        WalletCommand::Utxos(opts) => transaction::run_utxos(opts),
    }
}

pub(crate) use test_mint::run_test_mint;
pub(crate) use tree::run_create_tree;
