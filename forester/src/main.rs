use clap::Parser;
use forester::{cli::Cli, errors::ForesterError};

#[tokio::main]
#[allow(clippy::result_large_err)]
async fn main() -> Result<(), ForesterError> {
    dotenvy::dotenv().ok();
    forester::logging::setup();

    // Skeleton: parse args, then exit. Foresting logic was removed in the
    // shielded-pool reshape and will be reintroduced against the new
    // combined address+state tree type.
    let _cli = Cli::parse();
    tracing::info!("forester skeleton: no work to do");
    Ok(())
}
