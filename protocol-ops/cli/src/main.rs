use std::process::ExitCode;
mod circuit_features;
mod find_smart_accounts;
mod init_protocol;
mod rpc;
mod set_tree_fees;
mod transaction;
mod tree_fees;
mod update_protocol_config;
mod upgrade_shielded_pool;

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let outcome = match args.next().as_deref() {
        Some("circuit-features") => circuit_features::run(args.collect()),
        Some("init-protocol") => init_protocol::run(init_protocol::Options::parse(args.collect())),
        Some("find-smart-accounts") => {
            find_smart_accounts::run(find_smart_accounts::Options::parse(args.collect()))
        }
        Some("update-protocol-config") => {
            update_protocol_config::run(update_protocol_config::Options::parse(args.collect()))
        }
        Some("set-tree-fees") => set_tree_fees::run(set_tree_fees::Options::parse(args.collect())),
        Some("upgrade-shielded-pool") => {
            upgrade_shielded_pool::run(upgrade_shielded_pool::Options::parse(args.collect()))
        }
        Some("--help" | "-h") | None => {
            println!("Usage: zolana-protocol <command> [options]\n\nCommands:\n  init-protocol\n  find-smart-accounts\n  update-protocol-config\n  set-tree-fees\n  upgrade-shielded-pool\n  circuit-features\n\nRun a command with --help for its options.");
            return ExitCode::SUCCESS;
        }
        Some(command) => {
            eprintln!("unknown protocol command: {command}");
            return ExitCode::from(2);
        }
    };
    match outcome {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error:#}");
            ExitCode::FAILURE
        }
    }
}
