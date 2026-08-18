use std::sync::Arc;

use anyhow::Context;
use clap::Parser;
use log::info;
use zolana_client::{AsyncSolanaRpc, AsyncZolanaIndexer};
use zolana_ring_rpc::{
    audit::{asset_registry_from_chain, AuditService},
    config::{load_auditor_key, Args},
    server::run_server,
};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();
    let args = Args::parse();

    let auditor = load_auditor_key(&args.auditor_key_file)
        .with_context(|| format!("loading {}", args.auditor_key_file.display()))?;
    let assets = asset_registry_from_chain(&AsyncSolanaRpc::new(args.rpc_url.clone()))
        .await
        .context("loading the SPL asset registry")?;
    let indexer = AsyncZolanaIndexer::new(&args.indexer_url);
    let service = Arc::new(AuditService::new(auditor, indexer, assets));
    info!(
        "ring-rpc listening on port {} for auditor tag {}",
        args.port,
        hex::encode(service.auditor_view_tag())
    );

    let handle = run_server(service, args.port).await?;
    tokio::signal::ctrl_c().await?;
    handle.stop()?;
    handle.stopped().await;
    Ok(())
}
