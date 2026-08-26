use std::process::ExitCode;

fn main() -> ExitCode {
    match custom_ring_cli::parse_and_run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            let chain = format!("{:?}", anyhow::Error::from(error));
            eprintln!("Error: {}", custom_ring_cli::config::redact_text(&chain));
            ExitCode::FAILURE
        }
    }
}
