use std::sync::Arc;

use anyhow::Context;
use clap::Parser;
use log::info;
use zolana_ring_client::auditor_view_tag;
use zolana_ring_rpc::{
    public_key_path, run_server, write_auditor_key, write_root_secret, ChainSource, Cli, Command,
    Hub, KeyAccess, KeyFile, KeyKind, KeyMode, KeygenArgs, OriginPolicy, ServeArgs, ServerOptions,
    TransactionSource, Upstreams,
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
        Command::Keygen(args) => keygen(args),
    }
}

fn keygen(args: KeygenArgs) -> anyhow::Result<()> {
    match args.kind {
        KeyKind::Auditor => {
            let key = write_auditor_key(&args.out)
                .with_context(|| format!("writing {}", args.out.display()))?;
            println!("secret      {}", args.out.display());
            println!("public key  {}", public_key_path(&args.out)?.display());
            println!("auditor pk  {}", hex::encode(key.pubkey().as_bytes()));
            println!(
                "view tag    {}",
                hex::encode(auditor_view_tag(&key.pubkey()))
            );
        }
        KeyKind::Root => {
            write_root_secret(&args.out)
                .with_context(|| format!("writing {}", args.out.display()))?;
            println!("root secret {}", args.out.display());
        }
    }
    Ok(())
}

async fn serve(args: ServeArgs) -> anyhow::Result<()> {
    let source = ChainSource::connect(Upstreams {
        indexer_url: &args.indexer_url,
        rpc_url: &args.rpc_url,
        timeout: args.upstream_timeout(),
    })?;
    let genesis_hash = source
        .genesis_hash()
        .await
        .context("reading the cluster genesis hash")?;
    let options = ServerOptions {
        bind: args.bind,
        bind_policy: args.bind_policy(),
        port: args.port,
        max_connections: args.max_connections.get(),
        request_timeout: args.request_timeout(),
    };
    let origin_transport = args.origin_transport();
    let mut origin_policy = OriginPolicy::new(args.allow_origins).with_transport(origin_transport);
    if let Some(relying_party_id) = args.webauthn_rp_id {
        origin_policy = origin_policy.with_relying_party_id(relying_party_id);
    }
    let builder = Hub::builder(source, genesis_hash).with_origins(origin_policy.build()?);
    let hub = match (&args.auditor_key_file, &args.root_secret_file) {
        (Some(path), None) => {
            let ring = args
                .ring_program_id
                .ok_or_else(|| anyhow::anyhow!("--ring-program-id must name the served ring"))?;
            let auditor = KeyFile {
                path,
                access: if args.allow_shared_key_file {
                    KeyAccess::Shared
                } else {
                    KeyAccess::OwnerOnly
                },
            }
            .auditor_key()
            .with_context(|| format!("loading {}", path.display()))?;
            builder.local(ring, auditor)?
        }
        (None, Some(path)) => {
            let root = KeyFile {
                path,
                access: if args.allow_shared_key_file {
                    KeyAccess::Shared
                } else {
                    KeyAccess::OwnerOnly
                },
            }
            .root_secret()
            .with_context(|| format!("loading {}", path.display()))?;
            builder.derived(root)?
        }
        _ => anyhow::bail!("pass exactly one of --auditor-key-file and --root-secret-file"),
    };
    let hub = Arc::new(hub);
    info!("service pubkey {}", hub.service_pubkey());
    match (hub.mode(), hub.local_view_tag()) {
        (KeyMode::Local, Some(tag)) => info!(
            "ring-rpc listening on {}:{} for auditor tag {}",
            args.bind,
            args.port,
            hex::encode(tag)
        ),
        _ => info!(
            "ring-rpc listening on {}:{}, auditor keys derived per ring",
            args.bind, args.port
        ),
    }
    let handle = run_server(hub, options).await?;
    tokio::signal::ctrl_c().await?;
    info!("stopping");
    handle.stop()?;
    handle.stopped().await;
    Ok(())
}
