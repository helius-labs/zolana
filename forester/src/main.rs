use clap::Parser;
use forester::cli::Cli;

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();
    forester::logging::setup();

    let _cli = Cli::parse();
    tracing::info!("forester: no worker configured");
}
