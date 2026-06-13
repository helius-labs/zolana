mod args;
mod config;
mod http;
mod localnet;
mod process;
mod prover;

use anyhow::Result;
use clap::{CommandFactory, Parser};

use crate::{
    args::{Cli, CliCommand},
    localnet::run_test_validator,
    prover::run_start_prover,
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
        None => {
            Cli::command().print_help()?;
            println!();
            Ok(())
        }
    }
}
