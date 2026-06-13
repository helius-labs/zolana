use clap::Parser;
use forester::cli::Cli;

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();
    forester::logging::setup();

    // Skeleton: parse args, then exit. Foresting logic was removed in the
    // shielded-pool reshape and will be reintroduced against the new
    // combined address+state tree type.
    let _cli = Cli::parse();
    tracing::info!("forester skeleton: no work to do");
}
