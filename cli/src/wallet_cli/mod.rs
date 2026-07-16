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

// Re-export the per-command handlers so `main.rs` can dispatch the day-to-day
// wallet commands that now live at the top level (sync/balance/merge/deposit/
// transfer/withdraw) and the pool setup commands under `dev pool`.
pub(crate) use balance::run_balance;
pub(crate) use deposit::run_deposit;
pub(crate) use registry::run_merge;
pub(crate) use sync::run_sync;
pub(crate) use test_mint::run_test_mint;
pub(crate) use transaction::run_transfer;
pub(crate) use tree::run_create_tree;
pub(crate) use withdraw::run_withdraw;

const INDEXER_TIMEOUT: Duration = Duration::from_secs(120);
const INDEXER_POLL: Duration = Duration::from_millis(500);

pub(crate) fn run_wallet(command: WalletCommand) -> Result<()> {
    match command {
        WalletCommand::New(opts) => material::run_new(opts),
        WalletCommand::Address(opts) => material::run_address(opts),
        WalletCommand::Register(opts) => registry::run_register(opts),
    }
}
