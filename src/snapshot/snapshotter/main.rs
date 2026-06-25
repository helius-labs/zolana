use anyhow::{bail, Context, Result};
use clap::Parser;
use futures::StreamExt;
use log::{error, info};
use photon_indexer::common::{
    fetch_block_parent_slot, fetch_current_slot_with_infinite_retry, get_network_start_slot,
    get_rpc_client, setup_logging, setup_metrics, LoggingFormat,
};
use photon_indexer::ingester::fetchers::BlockStreamConfig;
use photon_indexer::snapshot::{
    get_snapshot_files_with_metadata, load_byte_stream_from_directory_adapter, DirectoryAdapter,
};
use std::future::pending;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use http_body_util::{combinators::UnsyncBoxBody, BodyExt, Full, StreamBody};
use hyper::body::{Frame, Incoming};
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::{
    rt::{TokioExecutor, TokioIo},
    server::conn::auto::Builder,
};
use tokio::net::TcpListener;

type ResponseBody = UnsyncBoxBody<Bytes, io::Error>;

/// Photon Snapshotter: a utility to create snapshots of Photon's state at regular intervals.
#[derive(Parser, Debug)]
#[command(version, about)]
struct Args {
    /// Port to expose the local snapshotter API
    #[arg(short, long, default_value_t = 8825)]
    port: u16,

    /// URL of the RPC server
    #[arg(short, long, default_value = "http://127.0.0.1:8899")]
    rpc_url: String,

    /// The start slot to begin indexing from. If "latest", the latest slot is used.
    #[arg(short, long)]
    start_slot: Option<String>,

    /// Logging format
    #[arg(short, long, default_value_t = LoggingFormat::Standard)]
    logging_format: LoggingFormat,

    /// Max number of blocks to fetch concurrently
    #[arg(short, long)]
    max_concurrent_block_fetches: Option<usize>,

    /// Snapshot directory
    #[arg(long)]
    snapshot_dir: Option<String>,

    /// R2 bucket name. The bucket must already exist. The endpoint url, region, access keys, and
    /// secret keys must be provided in the environment variables.
    #[arg(long)]
    r2_bucket: Option<String>,

    /// R2 prefix. All snapshots will be stored under this prefix in the R2 bucket.
    #[arg(long, default_value = "")]
    r2_prefix: String,

    /// GCS bucket name. The bucket must already exist. The credentials must be provided
    /// via Application Default Credentials (ADC) or environment variables.
    #[arg(long)]
    gcs_bucket: Option<String>,

    /// GCS prefix. All snapshots will be stored under this prefix in the GCS bucket.
    #[arg(long, default_value = "")]
    gcs_prefix: String,

    /// Incremental snapshot slots
    #[arg(long, default_value_t = 1000)]
    incremental_snapshot_interval_slots: u64,

    /// Full snapshot slots
    #[arg(long, default_value_t = 100_000)]
    snapshot_interval_slots: u64,

    /// Yellowstone gRPC URL
    #[arg(short, long, default_value = None)]
    grpc_url: Option<String>,

    /// Metrics endpoint in the format `host:port`
    #[arg(long, default_value = None)]
    metrics_endpoint: Option<String>,

    /// Disable snapshot generation and only serve snapshots
    #[arg(long, default_value_t = false)]
    disable_snapshot_generation: bool,

    /// Disable api server
    #[arg(long, default_value_t = false)]
    disable_api: bool,
}

async fn continuously_run_snapshotter(
    directory_adapter: Arc<DirectoryAdapter>,
    block_stream_config: BlockStreamConfig,
    full_snapshot_interval_slots: u64,
    incremental_snapshot_interval_slots: u64,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        if let Err(err) = photon_indexer::snapshot::update_snapshot(
            directory_adapter,
            block_stream_config,
            full_snapshot_interval_slots,
            incremental_snapshot_interval_slots,
        )
        .await
        {
            error!("Snapshot generation failed: {}", err);
        }
    })
}

async fn stream_bytes(
    directory_adapter: Arc<DirectoryAdapter>,
) -> Result<Response<ResponseBody>, hyper::http::Error> {
    let byte_stream = load_byte_stream_from_directory_adapter(directory_adapter).await;
    info!("Finished loading byte stream");
    let byte_stream = byte_stream.map(|bytes| {
        bytes
            .map_err(|e| {
                error!("Error reading byte: {:?}", e);
                io::Error::other("Stream Error")
            })
            .map(Frame::data)
    });

    Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "application/octet-stream")
        .body(StreamBody::new(byte_stream).boxed_unsync())
}

async fn fetch_slot(
    directory_adapter: Arc<DirectoryAdapter>,
) -> Result<Response<ResponseBody>, hyper::http::Error> {
    let snapshot_files = get_snapshot_files_with_metadata(directory_adapter.as_ref()).await;

    match snapshot_files {
        Ok(snapshot_files) => {
            let last_snapshot = snapshot_files.last();
            match last_snapshot {
                Some(snapshot) => Response::builder()
                    .status(StatusCode::OK)
                    .body(full_body(snapshot.end_slot.to_string())),
                None => Response::builder()
                    .status(StatusCode::NOT_FOUND)
                    .body(full_body("No snapshots found")),
            }
        }
        Err(e) => {
            error!("Error fetching snapshot files: {:?}", e);
            Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(full_body("Internal Server Error"))
        }
    }
}

async fn handle_request(
    req: Request<Incoming>,
    directory_adapter: Arc<DirectoryAdapter>,
) -> Result<Response<ResponseBody>, hyper::http::Error> {
    match req.uri().path() {
        "/download" => match stream_bytes(directory_adapter).await {
            Ok(response) => Ok(response),
            Err(e) => {
                error!("Error creating stream: {:?}", e);
                Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body(full_body("Internal Server Error"))
            }
        },
        "/health" | "/readiness" | "/healthz" => Response::builder()
            .status(StatusCode::OK)
            .body(full_body("OK")),
        "/slot" => fetch_slot(directory_adapter).await,
        _ => Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(full_body("404 Not Found")),
    }
    .map_err(|e| {
        error!("Error building response: {:?}", e);
        e
    })
}

fn full_body(body: impl Into<Bytes>) -> ResponseBody {
    Full::new(body.into())
        .map_err(|never| match never {})
        .boxed_unsync()
}

async fn create_server(
    port: u16,
    directory_adapter: Arc<DirectoryAdapter>,
) -> tokio::task::JoinHandle<()> {
    let addr = SocketAddr::from(([0, 0, 0, 0], port));

    tokio::spawn(async move {
        let listener = match TcpListener::bind(addr).await {
            Ok(listener) => listener,
            Err(e) => {
                error!("Failed to bind snapshotter API server: {}", e);
                return;
            }
        };
        info!("Listening on http://{}", addr);

        loop {
            let (stream, remote_addr) = match listener.accept().await {
                Ok(connection) => connection,
                Err(e) => {
                    error!("Failed to accept snapshotter API connection: {}", e);
                    continue;
                }
            };
            let directory_adapter = directory_adapter.clone();

            tokio::spawn(async move {
                let service = service_fn(move |req| handle_request(req, directory_adapter.clone()));
                if let Err(e) = Builder::new(TokioExecutor::new())
                    .serve_connection(TokioIo::new(stream), service)
                    .await
                {
                    error!("Snapshotter API error serving {}: {}", remote_addr, e);
                }
            });
        }
    })
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    setup_logging(args.logging_format);
    setup_metrics(args.metrics_endpoint)?;

    let rpc_client = get_rpc_client(&args.rpc_url);

    let directory_adapter = match (
        args.snapshot_dir.clone(),
        args.r2_bucket.clone(),
        args.gcs_bucket.clone(),
    ) {
        (Some(snapshot_dir), None, None) => {
            Arc::new(DirectoryAdapter::from_local_directory(snapshot_dir))
        }
        (None, Some(r2_bucket), None) => Arc::new(
            DirectoryAdapter::from_r2_bucket_and_prefix_and_env(r2_bucket, args.r2_prefix.clone())
                .await?,
        ),
        (None, None, Some(gcs_bucket)) => Arc::new(
            DirectoryAdapter::from_gcs_bucket_and_prefix_and_env(
                gcs_bucket,
                args.gcs_prefix.clone(),
            )
            .await?,
        ),
        _ => {
            bail!("Exactly one of snapshot_dir, r2_bucket, or gcs_bucket must be provided");
        }
    };
    let snapshotter_handle = if args.disable_snapshot_generation {
        None
    } else {
        info!("Starting snapshotter...");
        let snapshot_files = get_snapshot_files_with_metadata(directory_adapter.as_ref())
            .await
            .context("Failed to inspect snapshot source")?;

        let last_indexed_slot = match args.start_slot {
            Some(start_slot) => {
                if !snapshot_files.is_empty() {
                    bail!("Cannot specify start_slot when snapshot files are present");
                }
                let start_slot = match start_slot.as_str() {
                    "latest" => fetch_current_slot_with_infinite_retry(&rpc_client).await,
                    _ => {
                        let start_slot = start_slot
                            .parse::<u64>()
                            .with_context(|| format!("Invalid start slot '{}'", start_slot))?;
                        fetch_block_parent_slot(&rpc_client, start_slot).await?
                    }
                };
                start_slot
            }
            None => {
                if snapshot_files.is_empty() {
                    get_network_start_slot(&rpc_client).await
                } else {
                    snapshot_files
                        .last()
                        .context("Snapshot list became empty unexpectedly")?
                        .end_slot
                }
            }
        };
        info!("Starting from slot: {}", last_indexed_slot + 1);
        Some(
            continuously_run_snapshotter(
                directory_adapter.clone(),
                BlockStreamConfig {
                    rpc_client: rpc_client.clone(),
                    max_concurrent_block_fetches: args.max_concurrent_block_fetches.unwrap_or(20),
                    last_indexed_slot,
                    geyser_url: args.grpc_url.clone(),
                },
                args.snapshot_interval_slots,
                args.incremental_snapshot_interval_slots,
            )
            .await,
        )
    };
    let server_handle = if args.disable_api {
        None
    } else {
        Some(create_server(args.port, directory_adapter.clone()).await)
    };

    // Use `tokio::select!` to handle both the shutdown signal and task completions
    tokio::select! {
        // Handle shutdown signal (Ctrl+C)
        _ = tokio::signal::ctrl_c() => {
            info!("Received shutdown signal, aborting tasks...");
        }

        // If the snapshotter completes for some reason
        res = async {
            if let Some(snapshotter_handle) = snapshotter_handle {
                snapshotter_handle.await
            } else {
                pending().await
            }
        } => {
            match res {
                Ok(()) => info!("Snapshotter finished successfully"),
                Err(e) => error!("Snapshotter task failed: {:?}", e),
            }
        }
        // If the snapshotter completes for some reason
        res = async {
            if let Some(server_handle) = server_handle {
                server_handle.await
            } else {
                pending().await
            }
        } => {
            match res {
                Ok(()) => info!("Server finished successfully"),
                Err(e) => error!("Server task failed: {:?}", e),
            }
        }
    }
    Ok(())
}
