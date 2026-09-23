use std::process::ExitCode;

fn main() -> ExitCode {
    zolana_gnark_prover::setup_cli::main(&swap_prover::PROVER)
}
