//! The key setup binary every example prover ships:
//! `<bin> <circuit> <build-dir> [--rust-vk <path>]`. It generates fresh keys
//! into `<build-dir>` and emits the program's Rust verifying key source from
//! the new `vk.bin`.

use std::{path::PathBuf, process::ExitCode};

use crate::{Circuit, Prover};

struct Command<C> {
    circuit: C,
    build_dir: PathBuf,
    rust_vk: PathBuf,
}

/// The binary's `main`: `fn main() -> ExitCode { zolana_gnark_prover::setup_cli::main(&PROVER) }`.
pub fn main<C: Circuit>(prover: &Prover<C>) -> ExitCode {
    let mut args = std::env::args();
    let bin = args.next().unwrap_or_else(|| "setup".to_string());
    let command = match parse::<C>(args) {
        Ok(command) => command,
        Err(message) => {
            let circuits: Vec<&str> = C::ALL.iter().map(|circuit| circuit.name()).collect();
            eprintln!("error: {message}");
            eprintln!("usage: {bin} <circuit> <build-dir> [--rust-vk <path>]");
            eprintln!("  circuit: {}", circuits.join(" | "));
            eprintln!("  build-dir: where pk.bin / vk.bin are written");
            eprintln!("  --rust-vk: the generated Rust verifying key source, default <build-dir>/<circuit>_verifying_key.rs");
            return ExitCode::from(2);
        }
    };
    match run(prover, command) {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("error: {message}");
            ExitCode::FAILURE
        }
    }
}

fn parse<C: Circuit>(mut args: impl Iterator<Item = String>) -> Result<Command<C>, String> {
    let circuit_arg = args.next().ok_or("missing <circuit>")?;
    let circuit = C::ALL
        .iter()
        .copied()
        .find(|circuit| circuit.name() == circuit_arg)
        .ok_or_else(|| format!("unknown circuit {circuit_arg:?}"))?;
    let build_dir = PathBuf::from(args.next().ok_or("missing <build-dir>")?);
    let mut rust_vk = None;
    while let Some(flag) = args.next() {
        match flag.as_str() {
            "--rust-vk" => {
                rust_vk = Some(PathBuf::from(args.next().ok_or("--rust-vk missing value")?));
            }
            other => return Err(format!("unexpected arg {other:?}")),
        }
    }
    let rust_vk =
        rust_vk.unwrap_or_else(|| build_dir.join(format!("{}_verifying_key.rs", circuit.name())));
    Ok(Command {
        circuit,
        build_dir,
        rust_vk,
    })
}

fn run<C: Circuit>(prover: &Prover<C>, command: Command<C>) -> Result<(), String> {
    let Command {
        circuit,
        build_dir,
        rust_vk,
    } = command;
    println!("running setup for {}", circuit.name());
    println!("  build dir : {}", build_dir.display());
    println!("  rust vk   : {}", rust_vk.display());
    prover
        .setup(circuit, &build_dir)
        .map_err(|e| format!("setup failed: {e}"))?;

    let vk_bin = build_dir.join("vk.bin");
    println!("emitting Rust VK source from {}", vk_bin.display());
    let out_dir = rust_vk
        .parent()
        .ok_or("rust-vk path has no parent directory")?;
    let out_filename = rust_vk
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or("rust-vk path has no UTF-8 file name")?;
    groth16_solana::vk::gnark::generate_bsb22_vk_file(
        &vk_bin,
        out_dir,
        out_filename,
        "VERIFYINGKEY",
    )
    .map_err(|e| format!("failed to emit Rust verifying key source: {e:?}"))?;
    let formatted = std::process::Command::new("rustfmt")
        .arg("--edition")
        .arg("2021")
        .arg(&rust_vk)
        .status();
    if !formatted.is_ok_and(|status| status.success()) {
        eprintln!("warning: rustfmt did not format {}", rust_vk.display());
    }
    println!("done");
    Ok(())
}
