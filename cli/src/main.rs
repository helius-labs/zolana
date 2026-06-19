mod args;
mod config;
mod http;
mod localnet;
mod process;
mod prover;
mod wallet_cli;

use anyhow::Result;
use clap::{CommandFactory, Parser};

use crate::{
    args::{Cli, CliCommand},
    localnet::run_test_validator,
    prover::run_start_prover,
    wallet_cli::{run_balance, run_deposit, run_transfer, run_withdraw},
};

fn main() {
    if let Err(error) = run(Cli::parse()) {
        eprintln!("error: {error:#}");
        std::process::exit(1);
    }
}

fn run(cli: Cli) -> Result<()> {
    match cli.command {
        Some(CliCommand::TestValidator(opts)) => run_test_validator(*opts),
        Some(CliCommand::StartProver(opts)) => run_start_prover(opts),
        Some(CliCommand::Deposit(opts)) => run_deposit(opts),
        Some(CliCommand::Transfer(opts)) => run_transfer(opts),
        Some(CliCommand::Withdraw(opts)) => run_withdraw(opts),
        Some(CliCommand::Balance(opts)) => run_balance(opts),
        None => {
            Cli::command().print_help()?;
            println!();
            Ok(())
        }
    }
}
