use std::{env, process::Command};

use light_prover_client::helpers::get_light_cli_command;

fn main() {
    let mut args = env::args().skip(1);
    match args.next().as_deref() {
        Some("test-validator") => run_test_validator(args.collect()),
        Some("--help") | Some("-h") | None => print_help(),
        Some(command) => {
            eprintln!("unknown command: {command}");
            print_help();
            std::process::exit(2);
        }
    }
}

fn run_test_validator(args: Vec<String>) {
    let Some(light_cli) = get_light_cli_command() else {
        eprintln!(
            "failed to find Light CLI; install npm and @lightprotocol/zk-compression-cli, set LIGHT_CLI_BIN, or set LIGHT_CLI_CMD"
        );
        std::process::exit(1);
    };

    let extra_args = args
        .iter()
        .map(|arg| shell_quote(arg))
        .collect::<Vec<_>>()
        .join(" ");
    let command = if extra_args.is_empty() {
        format!("{light_cli} test-validator")
    } else {
        format!("{light_cli} test-validator {extra_args}")
    };

    let status = Command::new("sh")
        .arg("-c")
        .arg(command)
        .status()
        .expect("failed to spawn Light CLI test-validator");
    std::process::exit(status.code().unwrap_or(1));
}

fn print_help() {
    println!("zolana <command>");
    println!();
    println!("Commands:");
    println!("  test-validator    Start the local Light test validator");
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}
