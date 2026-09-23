use std::process::ExitCode;

fn main() -> ExitCode {
    zolana_gnark_ffi_prover::setup_cli::main(&timelock_escrow_prover::PROVER)
}
