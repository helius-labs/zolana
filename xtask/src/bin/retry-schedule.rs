//! Generates the retry schedule vectors that `@zolana/client` checks itself
//! against.
//!
//! Row C01 turns on whether the two ports wait the same amount, for the same
//! number of attempts, and stop for the same reason. `IndexerPollConfig` holds
//! all three answers in six lines of arithmetic -- the first delay is clamped
//! to the cap, each later delay doubles and re-clamps, and the attempt count is
//! one more than the retry count -- which reads the same in both languages and
//! diverges at the edges: a `delay_ms` above `max_delay_ms`, a doubling that
//! would leave `u64`, a zero delay that must not sleep, and `u32::MAX` retries.
//! This binary walks the real `backoff`, `attempts`, and `poll_until` over
//! those edges and records what Rust does.
//!
//! Sequences are recorded only for the small configurations; a `u32::MAX` retry
//! count is present for its attempt arithmetic alone.
//!
//! ```text
//! cargo run -p xtask --bin retry-schedule            # write the fixture
//! cargo run -p xtask --bin retry-schedule -- --check # fail on any drift
//! ```

use std::{cell::Cell, collections::BTreeMap, env, fs, path::PathBuf, process::ExitCode};

use anyhow::{bail, Context, Result};
use serde_json::{json, Map, Value};
use zolana_client::{ClientError, IndexerPollConfig};

const FIXTURE: &str = "sdk-libs/ts/vectors/retry-schedule-v1.json";

/// Above this retry count the delay sequence is too long to record, and only
/// the attempt arithmetic is interesting.
const MAX_RECORDED_RETRIES: u32 = 16;

/// Named configurations, each chosen for one edge of the schedule arithmetic.
fn configs() -> Vec<(&'static str, IndexerPollConfig)> {
    vec![
        ("default", IndexerPollConfig::default()),
        ("doublesThenCaps", IndexerPollConfig::new(4, 5, 12)),
        ("firstDelayClampedToCap", IndexerPollConfig::new(3, 20, 5)),
        ("noRetries", IndexerPollConfig::new(0, 100, 100)),
        ("zeroDelay", IndexerPollConfig::new(2, 0, 0)),
        ("capNeverReached", IndexerPollConfig::new(5, 1, u64::MAX)),
        (
            "doublingLeavesU64",
            IndexerPollConfig::new(3, u64::MAX / 2, u64::MAX),
        ),
        ("retryCountAtU32Max", IndexerPollConfig::new(u32::MAX, 0, 0)),
    ]
}

fn schedules() -> Vec<Value> {
    configs()
        .into_iter()
        .map(|(id, config)| {
            let mut case = json!({
                "id": id,
                "numRetries": config.num_retries.to_string(),
                "delayMs": config.delay_ms.to_string(),
                "maxDelayMs": config.max_delay_ms.to_string(),
                "attempts": config.attempts().to_string(),
            });
            if config.num_retries <= MAX_RECORDED_RETRIES {
                case["delaysMs"] = Value::Array(
                    config
                        .backoff()
                        .map(|delay| Value::String(delay.as_millis().to_string()))
                        .collect(),
                );
            }
            case
        })
        .collect()
}

/// What a poll spends and how it ends, per outcome the polled request can
/// reach. Only zero-delay configurations run here, so the recorded request
/// count is the schedule length and not a timing measurement.
fn polls() -> Vec<Value> {
    let config = IndexerPollConfig::new(3, 0, 0);
    vec![
        poll_case("rejectedResponse", config, |_| Ok::<u8, ClientError>(0)),
        poll_case("retryableIndexer", config, |_| {
            Err(ClientError::Indexer {
                method: "get_merkle_proofs",
                retryable: true,
            })
        }),
        poll_case("fatalIndexer", config, |_| {
            Err(ClientError::Indexer {
                method: "get_merkle_proofs",
                retryable: false,
            })
        }),
        poll_case("retryableRpc", config, |_| {
            Err(ClientError::Rpc("transport".to_string()))
        }),
        poll_case("indexerTimeout", config, |_| {
            Err(ClientError::IndexerTimeout)
        }),
        poll_case("fatalOther", config, |_| Err(ClientError::MissingOutput)),
        poll_case("acceptedOnTheThirdRequest", config, |requests| {
            if requests < 3 {
                Ok(0)
            } else {
                Ok(1)
            }
        }),
    ]
}

fn poll_case(
    id: &str,
    config: IndexerPollConfig,
    respond: impl Fn(u64) -> Result<u8, ClientError>,
) -> Value {
    let requests = Cell::new(0u64);
    let outcome = config.poll_until(
        || {
            requests.set(requests.get() + 1);
            respond(requests.get())
        },
        |response| *response == 1,
    );
    json!({
        "id": id,
        "requests": requests.get().to_string(),
        "outcome": match outcome {
            Ok(response) => json!({ "arm": "ok", "value": response.to_string() }),
            // The timeout carries the two values the port has to agree on, so
            // it is recorded field by field rather than as its message.
            Err(ClientError::PollTimedOut {
                attempts,
                last_cause,
            }) => json!({
                "arm": "err",
                "variant": "PollTimedOut",
                "attempts": attempts.to_string(),
                "lastCause": last_cause.map(|cause| format!("{cause:?}")),
            }),
            Err(ClientError::Indexer { retryable, .. }) => json!({
                "arm": "err",
                "variant": "Indexer",
                "retryable": retryable,
            }),
            Err(ClientError::MissingOutput) => json!({ "arm": "err", "variant": "MissingOutput" }),
            Err(other) => json!({ "arm": "err", "variant": other.to_string() }),
        },
    })
}

fn build() -> Value {
    json!({
        "schedules": schedules(),
        "polls": polls(),
    })
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("retry-schedule failed: {error:#}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<()> {
    let mut check = false;
    for arg in env::args().skip(1) {
        match arg.as_str() {
            "--check" => check = true,
            "--help" | "-h" => {
                println!(
                    "Generate the Rust-side retry schedule vectors.\n\nusage: cargo run -p xtask --bin retry-schedule -- [--check]"
                );
                return Ok(());
            }
            other => bail!("unknown argument {other}"),
        }
    }

    let fixture = canonicalize(&build());
    let rendered = format!("{}\n", serde_json::to_string_pretty(&fixture)?);
    let path = workspace_root()?.join(FIXTURE);

    if check {
        let current =
            fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
        if current != rendered {
            bail!("{FIXTURE} is stale; rerun `cargo run -p xtask --bin retry-schedule`");
        }
        return Ok(());
    }

    fs::write(&path, rendered).with_context(|| format!("write {}", path.display()))?;
    Ok(())
}

fn canonicalize(value: &Value) -> Value {
    match value {
        Value::Array(values) => Value::Array(values.iter().map(canonicalize).collect()),
        Value::Object(values) => Value::Object(
            values
                .iter()
                .map(|(key, value)| (key.clone(), canonicalize(value)))
                .collect::<BTreeMap<_, _>>()
                .into_iter()
                .collect::<Map<_, _>>(),
        ),
        _ => value.clone(),
    }
}

fn workspace_root() -> Result<PathBuf> {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest
        .parent()
        .map(PathBuf::from)
        .context("xtask has no parent directory")
}
