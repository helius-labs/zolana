use std::sync::Arc;

use anyhow::Context;
use clap::Parser;
use log::info;
use solana_signer::Signer;
use zolana_ring_client::auditor_view_tag;
use zolana_ring_rpc::{
    audit::{asset_registry_from_chain, ChainSource, Hub},
    config::{
        load_auditor_key, load_root_secret, public_key_path, write_auditor_key, Cli, Command,
        ServeArgs,
    },
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
    let source = ChainSource::new(&args.indexer_url, &args.rpc_url, args.upstream_timeout())?;
    let assets = asset_registry_from_chain(source.rpc())
        .await
        .context("loading the SPL asset registry")?;
    let hub = match (&args.auditor_key_file, &args.root_secret_file) {
        (Some(path), None) => Hub::local(
            args.ring_program_id.ok_or_else(|| {
                anyhow::anyhow!("--ring-program-id names the ring this key serves")
            })?,
            load_auditor_key(path, args.allow_shared_key_file)
                .with_context(|| format!("loading {}", path.display()))?,
            source,
            assets,
        ),
        (None, Some(path)) => {
            let genesis_hash = source
                .rpc()
                .client()
                .get_genesis_hash()
                .await
                .context("reading the cluster genesis hash")?
                .to_bytes();
            Hub::derived(
                load_root_secret(path, args.allow_shared_key_file)
                    .with_context(|| format!("loading {}", path.display()))?,
                genesis_hash,
                source,
                assets,
            )
        }
        _ => anyhow::bail!("pass exactly one of --auditor-key-file and --root-secret-file"),
    };
    let hub = Arc::new(hub);
    info!("service pubkey {}", hub.signer().pubkey());
    match hub.local_service() {
        Some(service) => info!(
            "ring-rpc listening on {}:{} for auditor tag {}",
            args.bind,
            args.port,
            hex::encode(service.auditor_view_tag())
        ),
        None => info!(
            "ring-rpc listening on {}:{}, auditor keys derived per ring",
            args.bind, args.port
        ),
    }

    let options = ServerOptions {
        bind: args.bind,
        port: args.port,
        max_connections: args.max_connections,
        request_timeout: args.request_timeout(),
        allow_origins: args.allow_origins,
    };
    let handle = run_server(hub, options).await?;
    tokio::signal::ctrl_c().await?;
    info!("stopping");
    handle.stop()?;
    handle.stopped().await;
    Ok(())
}
