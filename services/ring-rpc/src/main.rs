use std::sync::Arc;

use anyhow::Context;
use clap::Parser;
use log::info;
use zolana_ring_client::auditor_view_tag;
use zolana_ring_rpc::{
    audit::{asset_registry_from_chain, AuditService, ChainSource},
    config::{load_auditor_key, public_key_path, write_auditor_key, Cli, Command, ServeArgs},
    server::{run_server, ServerOptions},
};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();
    match Cli::parse().command {
        Command::Serve(args) => serve(args).await,
        Command::Keygen(args) => {
            let key = write_auditor_key(&args.out)
                .with_context(|| format!("writing {}", args.out.display()))?;
            println!("secret      {}", args.out.display());
            println!("public key  {}", public_key_path(&args.out).display());
            println!("auditor pk  {}", hex::encode(key.pubkey().as_bytes()));
            println!(
                "view tag    {}",
                hex::encode(auditor_view_tag(&key.pubkey()))
            );
            Ok(())
        }
    }
}

async fn serve(args: ServeArgs) -> anyhow::Result<()> {
    let auditor = load_auditor_key(&args.auditor_key_file, args.allow_shared_key_file)
        .with_context(|| format!("loading {}", args.auditor_key_file.display()))?;
    let source = ChainSource::new(&args.indexer_url, &args.rpc_url, args.upstream_timeout())?;
    let assets = asset_registry_from_chain(source.rpc())
        .await
        .context("loading the SPL asset registry")?;
    let service = Arc::new(AuditService::new(auditor, source, assets));
    info!(
        "ring-rpc listening on {}:{} for auditor tag {}",
        args.bind,
        args.port,
        hex::encode(service.auditor_view_tag())
    );

    let options = ServerOptions {
        bind: args.bind,
        port: args.port,
        max_connections: args.max_connections,
        request_timeout: args.request_timeout(),
        allow_origins: args.allow_origins,
    };
    let handle = run_server(service, options).await?;
    tokio::signal::ctrl_c().await?;
    info!("stopping");
    handle.stop()?;
    handle.stopped().await;
    Ok(())
}
