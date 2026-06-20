mod balance;
mod deposit;
mod material;
mod registry;
mod sync;
mod transaction;
mod tree;
mod util;
mod withdraw;

use std::time::Duration;

use anyhow::Result;

use crate::args::WalletCommand;

const INDEXER_TIMEOUT: Duration = Duration::from_secs(120);
const INDEXER_POLL: Duration = Duration::from_millis(500);

pub(crate) fn run_wallet(command: WalletCommand) -> Result<()> {
    match command {
        WalletCommand::Init(opts) => material::run_init(opts),
        WalletCommand::CreateTree(opts) => tree::run_create_tree(opts),
        WalletCommand::Sync(opts) => sync::run_sync(opts),
        WalletCommand::Balance(opts) => balance::run_balance(opts),
        WalletCommand::Deposit(opts) => deposit::run_deposit(opts),
        WalletCommand::Transfer(opts) => transaction::run_transfer(opts),
        WalletCommand::Withdraw(opts) => withdraw::run_withdraw(opts),
    }
}
