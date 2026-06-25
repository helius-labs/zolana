use std::{fs::File, time::Duration};

use anyhow::{bail, Context, Result};
use async_stream::stream;
use clap::Parser;
use futures::{pin_mut, StreamExt};
use jsonrpsee::server::ServerHandle;
use log::{error, info, warn};
use photon_indexer::api::{self, api::PhotonApi};

use photon_indexer::common::{
    fetch_block_parent_slot, fetch_current_slot_with_infinite_retry, get_network_start_slot,
    get_rpc_client, setup_logging, setup_metrics, setup_pg_pool, LoggingFormat,
};

use photon_indexer::ingester::fetchers::BlockStreamConfig;
use photon_indexer::ingester::indexer::{
    fetch_last_indexed_slot_with_infinite_retry, index_block_stream,
};
use photon_indexer::migration::{
    sea_orm::{DatabaseBackend, DatabaseConnection, SqlxPostgresConnector, SqlxSqliteConnector},
    MigratorTrait, RingsMigrator,
};

use photon_indexer::monitor::continuously_monitor_photon;
use photon_indexer::snapshot::{
    get_snapshot_files_with_metadata, load_block_stream_from_directory_adapter, DirectoryAdapter,
};
use solana_client::nonblocking::rpc_client::RpcClient;
use sqlx::{
    sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous},
    SqlitePool,
};
use std::env::temp_dir;
use std::sync::Arc;

const SQLITE_BUSY_TIMEOUT: Duration = Duration::from_secs(30);

/// Photon: the Rings indexer
#[derive(Parser, Debug)]
#[command(version, about)]
struct Args {
    /// Port to expose the local Photon API
    // We use a random default port to avoid conflicts with other services
    #[arg(short, long, default_value_t = 8784)]
    port: u16,

    /// URL of the RPC server
    #[arg(short, long, default_value = "http://127.0.0.1:8899")]
    rpc_url: String,

    /// DB URL to store indexing data. By default we use an in-memory SQLite database.
    #[arg(short, long)]
    db_url: Option<String>,

    /// The start slot to begin indexing from. Defaults to the last indexed slot in the database plus
    /// one.
    #[arg(short, long)]
    start_slot: Option<String>,

    /// Max database connections to use in database pool
    #[arg(long, default_value_t = 10)]
    max_db_conn: u32,

    /// Logging format
    #[arg(short, long, default_value_t = LoggingFormat::Standard)]
    logging_format: LoggingFormat,

    /// Max number of blocks to fetch concurrently. Generally, this should be set to be as high
    /// as possible without reaching RPC rate limits.
    #[arg(short, long)]
    max_concurrent_block_fetches: Option<usize>,

    #[arg(short, long, default_value = None)]
    /// Yellowstone gRPC URL. If it's inputed, then the indexer will use gRPC to fetch new blocks
    /// instead of polling. It will still use RPC to fetch blocks if
    grpc_url: Option<String>,

    /// Disable indexing
    #[arg(long, action = clap::ArgAction::SetTrue)]
    disable_indexing: bool,

    /// Disable API
    #[arg(long, action = clap::ArgAction::SetTrue)]
    disable_api: bool,

    /// Metrics endpoint in the format `host:port`
    /// If provided, metrics will be sent to the specified statsd server.
    #[arg(long, default_value = None)]
    metrics_endpoint: Option<String>,

    /// Max concurrent HTTP connections for the JSON-RPC server (jsonrpsee).
    /// Connections beyond this limit receive HTTP 429.
    #[arg(long, default_value_t = 1024)]
    max_http_connections: u32,

    /// Local directory containing Rings BlockInfo snapshot files.
    #[arg(long)]
    snapshot_dir: Option<String>,

    /// R2 bucket name for Rings BlockInfo snapshots.
    #[arg(long)]
    r2_bucket: Option<String>,

    /// R2 prefix for Rings BlockInfo snapshot files.
    #[arg(long, default_value = "")]
    r2_prefix: String,

    /// GCS bucket name for Rings BlockInfo snapshots.
    #[arg(long)]
    gcs_bucket: Option<String>,

    /// GCS prefix for Rings BlockInfo snapshot files.
    #[arg(long, default_value = "")]
    gcs_prefix: String,
}

async fn start_api_server(
    db: Arc<DatabaseConnection>,
    rpc_client: Arc<RpcClient>,
    api_port: u16,
    max_http_connections: u32,
) -> Result<ServerHandle> {
    let api = PhotonApi::new(db, rpc_client);
    api::rpc_server::run_server(api, api_port, max_http_connections)
        .await
        .context("Failed to start API server")
}

async fn setup_temporary_sqlite_database_pool(max_connections: u32) -> Result<SqlitePool> {
    let dir = temp_dir();
    if !dir.exists() {
        std::fs::create_dir_all(&dir).context("Failed to create temp directory")?;
    }
    let db_name = "photon_indexer.db";
    let path = dir.join(db_name);
    let wal_path = dir.join(format!("{db_name}-wal"));
    let shm_path = dir.join(format!("{db_name}-shm"));
    for path in [&path, &wal_path, &shm_path] {
        if path.exists() {
            std::fs::remove_file(path)
                .with_context(|| format!("Failed to remove old SQLite file {:?}", path))?;
        }
    }
    info!("Creating temporary SQLite database at: {:?}", path);
    File::create(&path).with_context(|| format!("Failed to create SQLite file {:?}", path))?;
    let db_path = format!(
        "sqlite:////{}",
        path.to_str()
            .with_context(|| format!("SQLite path {:?} is not valid UTF-8", path))?
    );
    setup_sqlite_pool(&db_path, max_connections).await
}

async fn setup_sqlite_pool(db_url: &str, max_connections: u32) -> Result<SqlitePool> {
    let options: SqliteConnectOptions = db_url
        .parse::<SqliteConnectOptions>()
        .context("Failed to parse SQLite database URL")?
        .create_if_missing(true)
        .journal_mode(SqliteJournalMode::Wal)
        .synchronous(SqliteSynchronous::Normal)
        .busy_timeout(SQLITE_BUSY_TIMEOUT);
    SqlitePoolOptions::new()
        .max_connections(max_connections)
        .min_connections(1)
        .acquire_timeout(SQLITE_BUSY_TIMEOUT)
        .connect_with(options)
        .await
        .context("Failed to connect to SQLite database")
}

pub fn parse_db_type(db_url: &str) -> Result<DatabaseBackend> {
    if db_url.starts_with("postgres://") {
        Ok(DatabaseBackend::Postgres)
    } else if db_url.starts_with("sqlite://") {
        Ok(DatabaseBackend::Sqlite)
    } else {
        bail!("Unsupported database type: {}", db_url)
    }
}

async fn setup_database_connection(
    db_url: Option<String>,
    max_connections: u32,
) -> Result<Arc<DatabaseConnection>> {
    Ok(Arc::new(match db_url {
        Some(db_url) => {
            let db_type = parse_db_type(&db_url)?;
            match db_type {
                DatabaseBackend::Postgres => SqlxPostgresConnector::from_sqlx_postgres_pool(
                    setup_pg_pool(&db_url, max_connections).await?,
                ),
                DatabaseBackend::Sqlite => SqlxSqliteConnector::from_sqlx_sqlite_pool(
                    setup_sqlite_pool(&db_url, max_connections).await?,
                ),
                backend => bail!("Unsupported database backend: {:?}", backend),
            }
        }
        None => SqlxSqliteConnector::from_sqlx_sqlite_pool(
            setup_temporary_sqlite_database_pool(max_connections).await?,
        ),
    }))
}

fn continuously_index_new_blocks(
    block_stream_config: BlockStreamConfig,
    db: Arc<DatabaseConnection>,
    rpc_client: Arc<RpcClient>,
    last_indexed_slot: u64,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let block_stream = block_stream_config.load_block_stream();
        index_block_stream(
            block_stream,
            db,
            rpc_client.clone(),
            last_indexed_slot,
            None,
        )
        .await;
    })
}

async fn snapshot_directory_adapter(args: &Args) -> Result<Option<Arc<DirectoryAdapter>>> {
    Ok(
        match (
            args.snapshot_dir.clone(),
            args.r2_bucket.clone(),
            args.gcs_bucket.clone(),
        ) {
            (Some(snapshot_dir), None, None) => Some(Arc::new(
                DirectoryAdapter::from_local_directory(snapshot_dir),
            )),
            (None, Some(r2_bucket), None) => Some(Arc::new(
                DirectoryAdapter::from_r2_bucket_and_prefix_and_env(
                    r2_bucket,
                    args.r2_prefix.clone(),
                )
                .await?,
            )),
            (None, None, Some(gcs_bucket)) => Some(Arc::new(
                DirectoryAdapter::from_gcs_bucket_and_prefix_and_env(
                    gcs_bucket,
                    args.gcs_prefix.clone(),
                )
                .await?,
            )),
            (None, None, None) => None,
            _ => bail!("Specify only one of --snapshot-dir, --r2-bucket, or --gcs-bucket"),
        },
    )
}

async fn load_snapshot_if_present(
    args: &Args,
    db_conn: Arc<DatabaseConnection>,
    rpc_client: Arc<RpcClient>,
) -> Result<()> {
    let Some(directory_adapter) = snapshot_directory_adapter(args).await? else {
        return Ok(());
    };

    let snapshot_files = get_snapshot_files_with_metadata(directory_adapter.as_ref())
        .await
        .context("Failed to inspect snapshot source")?;
    let Some(last_snapshot) = snapshot_files.last() else {
        info!("No snapshot files found");
        return Ok(());
    };

    let snapshot_end_slot = last_snapshot.end_slot;
    if let Some(slot) = fetch_last_indexed_slot_with_infinite_retry(db_conn.as_ref()).await {
        let slot = u64::try_from(slot)
            .with_context(|| format!("Last indexed slot {} is negative", slot))?;
        if slot >= snapshot_end_slot {
            info!(
                "Skipping snapshot load; database is already indexed through slot {}",
                snapshot_end_slot
            );
            return Ok(());
        }
    }

    info!("Syncing tree metadata before loading snapshot...");
    if let Err(err) = photon_indexer::monitor::tree_metadata_sync::sync_tree_metadata(
        rpc_client.as_ref(),
        db_conn.as_ref(),
    )
    .await
    {
        error!("Failed to sync tree metadata before snapshot load: {}", err);
        return Err(err).context("Failed to sync tree metadata before snapshot load");
    }

    info!("Loading Rings BlockInfo snapshot through slot {snapshot_end_slot}...");
    let block_stream = load_block_stream_from_directory_adapter(directory_adapter.clone()).await;
    pin_mut!(block_stream);
    let Some(first_blocks) = block_stream.next().await else {
        info!("Snapshot source was empty");
        return Ok(());
    };
    let Some(first_block) = first_blocks.first() else {
        info!("Snapshot contained no blocks");
        return Ok(());
    };
    let last_indexed_slot = first_block.metadata.parent_slot;
    let replay_stream = stream! {
        yield first_blocks;
        while let Some(blocks) = block_stream.next().await {
            yield blocks;
        }
    };

    index_block_stream(
        replay_stream,
        db_conn,
        rpc_client,
        last_indexed_slot,
        Some(snapshot_end_slot),
    )
    .await;
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    setup_logging(args.logging_format.clone());
    setup_metrics(args.metrics_endpoint.clone())?;

    let db_conn = setup_database_connection(args.db_url.clone(), args.max_db_conn).await?;
    info!("Running Photon as a Rings indexer");

    if args.db_url.is_none() {
        info!("Running migrations...");
        RingsMigrator::up(db_conn.as_ref(), None)
            .await
            .context("Failed to run migrations")?;
    }

    let is_rpc_node_local = args.rpc_url.contains("127.0.0.1");
    let rpc_client = get_rpc_client(&args.rpc_url);

    load_snapshot_if_present(&args, db_conn.clone(), rpc_client.clone()).await?;

    let (indexer_handle, monitor_handle) = match args.disable_indexing {
        true => {
            info!("Indexing is disabled");
            (None, None)
        }
        false => {
            info!("Starting indexer...");

            info!("Syncing tree metadata...");
            if let Err(e) = photon_indexer::monitor::tree_metadata_sync::sync_tree_metadata(
                rpc_client.as_ref(),
                db_conn.as_ref(),
            )
            .await
            {
                warn!("Failed to sync tree metadata on startup: {}. Will retry in background monitor.", e);
            } else {
                info!("Tree metadata sync completed successfully");
            }

            // For localnet we can safely use a large batch size to speed up indexing.
            let max_concurrent_block_fetches = match args.max_concurrent_block_fetches {
                Some(max_concurrent_block_fetches) => max_concurrent_block_fetches,
                None => {
                    if is_rpc_node_local {
                        200
                    } else {
                        20
                    }
                }
            };
            let last_indexed_slot = match args.start_slot {
                Some(start_slot) => match start_slot.as_str() {
                    "latest" => fetch_current_slot_with_infinite_retry(&rpc_client).await,
                    _ => {
                        let start_slot = start_slot
                            .parse::<u64>()
                            .with_context(|| format!("Invalid start slot '{}'", start_slot))?;
                        fetch_block_parent_slot(&rpc_client, start_slot).await?
                    }
                },
                None => match fetch_last_indexed_slot_with_infinite_retry(db_conn.as_ref()).await {
                    Some(slot) => u64::try_from(slot)
                        .with_context(|| format!("Last indexed slot {} is negative", slot))?,
                    None => get_network_start_slot(&rpc_client).await,
                },
            };

            let block_stream_config = BlockStreamConfig {
                rpc_client: rpc_client.clone(),
                max_concurrent_block_fetches,
                last_indexed_slot,
                geyser_url: args.grpc_url,
            };

            (
                Some(continuously_index_new_blocks(
                    block_stream_config,
                    db_conn.clone(),
                    rpc_client.clone(),
                    last_indexed_slot,
                )),
                Some(continuously_monitor_photon(
                    db_conn.clone(),
                    rpc_client.clone(),
                )),
            )
        }
    };

    info!(
        "Starting API server with port {}, max_http_connections={}...",
        args.port, args.max_http_connections
    );
    let api_handler = if args.disable_api {
        None
    } else {
        Some(
            start_api_server(
                db_conn.clone(),
                rpc_client.clone(),
                args.port,
                args.max_http_connections,
            )
            .await?,
        )
    };

    match tokio::signal::ctrl_c().await {
        Ok(()) => {
            if let Some(indexer_handle) = indexer_handle {
                info!("Shutting down indexer...");
                indexer_handle.abort();
                if let Ok(()) = indexer_handle.await {
                    warn!("Indexer task exited cleanly after abort request");
                }
            }
            if let Some(api_handler) = &api_handler {
                info!("Shutting down API server...");
                api_handler.stop().context("Failed to stop API server")?;
            }

            if let Some(monitor_handle) = monitor_handle {
                info!("Shutting down monitor...");
                monitor_handle.abort();
                if let Ok(()) = monitor_handle.await {
                    warn!("Monitor task exited cleanly after abort request");
                }
            }
        }
        Err(err) => {
            error!("Unable to listen for shutdown signal: {}", err);
        }
    }
    // We need to wait for the API server to stop to ensure that all clean up is done
    if let Some(api_handler) = api_handler {
        tokio::spawn(api_handler.stopped());
    }
    Ok(())
}
