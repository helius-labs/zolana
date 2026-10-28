use std::process::ExitCode;

fn main() -> ExitCode {
    spr_gnark_ffi_prover::setup_cli::main(&swap_prover::PROVER)
}
