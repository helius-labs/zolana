use std::process::ExitCode;

fn main() -> ExitCode {
    spr_gnark_ffi_prover::setup_cli::main(&compression_example_prover::PROVER)
}
