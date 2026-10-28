use std::process::ExitCode;

fn main() -> ExitCode {
    spr_gnark_ffi_prover::setup_cli::main(&dynamic_swap_prover::PROVER)
}
