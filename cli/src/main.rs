mod args;
mod cli_config;
mod config;
mod config_cmd;
mod http;
mod localnet;
mod process;
mod prover;
mod release;
mod wallet_cli;

use anyhow::Result;
use clap::{CommandFactory, Parser};

use crate::{
    args::{Cli, CliCommand, DevCommand, DevPoolCommand, DevProverCommand},
    config_cmd::run_config,
    localnet::run_test_validator,
    prover::run_start_prover,
    wallet_cli::{
        run_balance, run_create_tree, run_deposit, run_merge, run_sync, run_test_mint,
        run_transfer, run_wallet, run_withdraw,
    },
};

fn main() {
    if let Err(error) = run(Cli::parse()) {
        eprintln!("error: {error:#}");
        std::process::exit(1);
    }
}

fn run(cli: Cli) -> Result<()> {
    match cli.command {
        Some(CliCommand::Config { command }) => run_config(command),
        Some(CliCommand::Wallet { command }) => run_wallet(command),
        Some(CliCommand::Dev { command }) => run_dev(command),
        Some(CliCommand::TestEnv(opts)) => run_test_validator(*opts),
        Some(CliCommand::Sync(opts)) => run_sync(opts),
        Some(CliCommand::Balance(opts)) => run_balance(opts),
        Some(CliCommand::Deposit(opts)) => run_deposit(opts),
        Some(CliCommand::Transfer(opts)) => run_transfer(opts),
        Some(CliCommand::Withdraw(opts)) => run_withdraw(opts),
        Some(CliCommand::Merge(opts)) => run_merge(opts),
        None => {
            Cli::command().print_help()?;
            println!();
            Ok(())
        }
    }
}

fn run_dev(command: DevCommand) -> Result<()> {
    match command {
        DevCommand::Start(opts) => run_test_validator(*opts),
        DevCommand::Prover {
            command: DevProverCommand::Start(opts),
        } => run_start_prover(opts),
        DevCommand::Pool { command } => match command {
            DevPoolCommand::CreateTree(opts) => run_create_tree(opts),
            DevPoolCommand::TestMint(opts) => run_test_mint(opts),
        },
    }
}
