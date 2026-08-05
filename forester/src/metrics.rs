//! Prometheus metrics for the forester, served over plain HTTP.
//!
//! Only the metrics this forester can actually populate are served. The names
//! come from `forester/metrics-contract.json`, and `contract_covers_served_names`
//! below asserts that every served name appears there.
//!
//! Six contract entries are deliberately NOT served: `forester_epoch_detected`,
//! `forester_epoch_registered`, `registered_foresters`, and the three
//! `epoch`-labelled transaction metrics. They describe the upstream Light
//! Protocol epoch/registry design; this forester submits through a smart-account
//! vault and has no epoch concept, so there is nothing to report. A gauge that is
//! permanently zero reads as healthy data, which is worse than an absent one.
//!
//! No HTTP or metrics dependency: the forester is a small synchronous binary that
//! pulls neither tokio nor hyper, and the Prometheus text format is a few lines.
//! Adding an async runtime to expose seven gauges would change the binary's
//! runtime model for no benefit.

use std::{
    collections::BTreeMap,
    io::{BufRead, BufReader, Write},
    net::{TcpListener, TcpStream},
    sync::{Mutex, OnceLock},
    time::{SystemTime, UNIX_EPOCH},
};

/// A metric sample: label pairs (sorted, so output is deterministic) and a value.
type Sample = (BTreeMap<&'static str, String>, f64);

#[derive(Default)]
struct Registry {
    /// Gauges keyed by metric name, each holding its label sets.
    gauges: BTreeMap<&'static str, Vec<Sample>>,
    /// Counters keyed by metric name. Monotonic; only ever incremented.
    counters: BTreeMap<&'static str, Vec<Sample>>,
}

fn registry() -> &'static Mutex<Registry> {
    static REGISTRY: OnceLock<Mutex<Registry>> = OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(Registry::default()))
}

/// Metric names served by this forester. Every one must appear in the contract
/// file; see `contract_covers_served_names`.
pub mod names {
    pub const QUEUE_LENGTH: &str = "queue_length";
    pub const QUEUE_CAPACITY: &str = "queue_capacity";
    pub const LAST_RUN_TIMESTAMP: &str = "forester_last_run_timestamp";
    pub const SOL_BALANCE: &str = "forester_sol_balance";
    pub const TRANSACTIONS_FAILED: &str = "forester_transactions_failed_total";
    pub const BATCHES_SUBMITTED: &str = "forester_batches_submitted_total";
    pub const INDEXER_RESPONSE_SECONDS: &str = "forester_indexer_response_time_seconds";
    pub const INDEXER_PROOF_COUNT: &str = "forester_indexer_proof_count";

    pub const ALL: &[&str] = &[
        QUEUE_LENGTH,
        QUEUE_CAPACITY,
        LAST_RUN_TIMESTAMP,
        SOL_BALANCE,
        TRANSACTIONS_FAILED,
        BATCHES_SUBMITTED,
        INDEXER_RESPONSE_SECONDS,
        INDEXER_PROOF_COUNT,
    ];
}

fn set(kind: &mut BTreeMap<&'static str, Vec<Sample>>, name: &'static str, labels: Sample) {
    let series = kind.entry(name).or_default();
    match series
        .iter_mut()
        .find(|(existing, _)| *existing == labels.0)
    {
        Some(slot) => slot.1 = labels.1,
        None => series.push(labels),
    }
}

fn labels(pairs: &[(&'static str, &str)]) -> BTreeMap<&'static str, String> {
    pairs
        .iter()
        .map(|(key, value)| (*key, (*value).to_string()))
        .collect()
}

/// Record the nullifier queue's depth and capacity for one tree.
pub fn set_queue(tree_pubkey: &str, length: u64, capacity: u64) {
    let tags = labels(&[("tree_type", "nullifier"), ("tree_pubkey", tree_pubkey)]);
    let mut registry = registry().lock().expect("metrics registry poisoned");
    set(
        &mut registry.gauges,
        names::QUEUE_LENGTH,
        (tags.clone(), length as f64),
    );
    set(
        &mut registry.gauges,
        names::QUEUE_CAPACITY,
        (tags, capacity as f64),
    );
}

/// Stamp the current time as the last completed run iteration.
///
/// This is the metric that answers "is the forester alive?", which is currently
/// unanswerable without reading logs.
pub fn mark_run() {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|since| since.as_secs() as f64)
        .unwrap_or(0.0);
    let mut registry = registry().lock().expect("metrics registry poisoned");
    set(
        &mut registry.gauges,
        names::LAST_RUN_TIMESTAMP,
        (BTreeMap::new(), now),
    );
}

/// Record the fee payer's balance in SOL.
///
/// The forester silently stops being able to submit when this reaches zero, so it
/// is the metric worth alerting on.
pub fn set_sol_balance(pubkey: &str, lamports: u64) {
    let mut registry = registry().lock().expect("metrics registry poisoned");
    set(
        &mut registry.gauges,
        names::SOL_BALANCE,
        (
            labels(&[("pubkey", pubkey)]),
            lamports as f64 / 1_000_000_000.0,
        ),
    );
}

/// Add to a counter series, creating it on first use.
fn add(name: &'static str, tags: BTreeMap<&'static str, String>, delta: f64) {
    let mut registry = registry().lock().expect("metrics registry poisoned");
    let series = registry.counters.entry(name).or_default();
    match series.iter_mut().find(|(existing, _)| *existing == tags) {
        Some(slot) => slot.1 += delta,
        None => series.push((tags, delta)),
    }
}

/// Count a failed submission, bucketed by a short stable reason.
pub fn count_failure(reason: &str) {
    add(
        names::TRANSACTIONS_FAILED,
        labels(&[("reason", reason)]),
        1.0,
    );
}

/// Count zkp-batches successfully submitted on-chain for one tree.
///
/// This fork's stand-in for the contract's `forester_transactions_processed_total`,
/// which is keyed by an epoch this forester does not have. Together with
/// `forester_last_run_timestamp` it separates "alive" from "making progress": a
/// forester that loops without submitting is live and useless.
pub fn count_batches_submitted(tree_pubkey: &str, batches: u64) {
    if batches == 0 {
        return;
    }
    add(
        names::BATCHES_SUBMITTED,
        labels(&[("tree_type", "nullifier"), ("tree_pubkey", tree_pubkey)]),
        batches as f64,
    );
}

/// Record how long an indexer call took.
pub fn observe_indexer(operation: &str, seconds: f64) {
    let mut registry = registry().lock().expect("metrics registry poisoned");
    set(
        &mut registry.gauges,
        names::INDEXER_RESPONSE_SECONDS,
        (
            labels(&[("operation", operation), ("tree_type", "nullifier")]),
            seconds,
        ),
    );
}

/// Record a count the indexer reported for a tree, e.g. queued values fetched.
pub fn set_indexer_proof_count(tree_pubkey: &str, metric: &str, count: u64) {
    let mut registry = registry().lock().expect("metrics registry poisoned");
    set(
        &mut registry.gauges,
        names::INDEXER_PROOF_COUNT,
        (
            labels(&[
                ("tree_type", "nullifier"),
                ("tree_pubkey", tree_pubkey),
                ("metric", metric),
            ]),
            count as f64,
        ),
    );
}

fn render_series(out: &mut String, kind: &str, series: &BTreeMap<&'static str, Vec<Sample>>) {
    for (name, samples) in series {
        if samples.is_empty() {
            continue;
        }
        out.push_str(&format!("# TYPE {name} {kind}\n"));
        for (tags, value) in samples {
            if tags.is_empty() {
                out.push_str(&format!("{name} {value}\n"));
                continue;
            }
            let rendered = tags
                .iter()
                .map(|(key, value)| format!("{key}=\"{}\"", escape(value)))
                .collect::<Vec<_>>()
                .join(",");
            out.push_str(&format!("{name}{{{rendered}}} {value}\n"));
        }
    }
}

/// Escape a label value per the Prometheus exposition format.
fn escape(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

/// Render the registry in Prometheus text exposition format.
pub fn render() -> String {
    let registry = registry().lock().expect("metrics registry poisoned");
    let mut out = String::new();
    render_series(&mut out, "gauge", &registry.gauges);
    render_series(&mut out, "counter", &registry.counters);
    out
}

/// Serve `GET /metrics` on `address` from a background thread.
///
/// Failure to bind is logged and ignored: metrics are observability, and the
/// forester must keep draining the queue without them.
pub fn serve(address: &str) {
    let listener = match TcpListener::bind(address) {
        Ok(listener) => listener,
        Err(err) => {
            tracing::warn!(%address, %err, "metrics server failed to bind; continuing without it");
            return;
        }
    };
    tracing::info!(%address, "metrics server listening on /metrics");
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            match stream {
                Ok(stream) => {
                    if let Err(err) = respond(stream) {
                        tracing::debug!(%err, "metrics request failed");
                    }
                }
                Err(err) => tracing::debug!(%err, "metrics connection failed"),
            }
        }
    });
}

fn respond(mut stream: TcpStream) -> std::io::Result<()> {
    let mut request_line = String::new();
    BufReader::new(&stream).read_line(&mut request_line)?;
    let path = request_line.split_whitespace().nth(1).unwrap_or("");
    let (status, body) = if path == "/metrics" {
        ("200 OK", render())
    } else {
        ("404 Not Found", String::new())
    };
    stream.write_all(
        format!(
            "HTTP/1.1 {status}\r\nContent-Type: text/plain; version=0.0.4\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
        .as_bytes(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The contract file calls itself the single source of truth for metric
    /// names, but nothing in this crate validated against it, which is how six of
    /// its entries came to describe a design this forester does not have.
    ///
    /// Asserts a SUBSET, not equality: the k8s monitoring repo also validates
    /// against this file, so entries we do not serve must stay listed rather than
    /// be deleted from under it.
    #[test]
    fn contract_covers_served_names() {
        let contract = include_str!("../metrics-contract.json");
        let parsed: serde_json::Value = serde_json::from_str(contract).expect("contract is JSON");
        let listed: Vec<&str> = parsed["metrics"]
            .as_array()
            .expect("metrics is an array")
            .iter()
            .map(|metric| metric["name"].as_str().expect("name is a string"))
            .collect();

        for served in names::ALL {
            assert!(
                listed.contains(served),
                "served metric {served} is absent from metrics-contract.json"
            );
        }
    }

    #[test]
    fn render_emits_labels_and_types() {
        set_queue("treeAbc", 42, 500);
        let out = render();
        assert!(out.contains("# TYPE queue_length gauge"));
        assert!(out.contains(r#"queue_length{tree_pubkey="treeAbc",tree_type="nullifier"} 42"#));
        assert!(out.contains(r#"queue_capacity{tree_pubkey="treeAbc",tree_type="nullifier"} 500"#));
    }

    #[test]
    fn balance_is_reported_in_sol_not_lamports() {
        set_sol_balance("payerAbc", 2_500_000_000);
        assert!(render().contains(r#"forester_sol_balance{pubkey="payerAbc"} 2.5"#));
    }

    #[test]
    fn failures_accumulate_per_reason() {
        count_failure("metrics-test-reason");
        count_failure("metrics-test-reason");
        let out = render();
        assert!(out.contains("# TYPE forester_transactions_failed_total counter"));
        assert!(
            out.contains(r#"forester_transactions_failed_total{reason="metrics-test-reason"} 2"#),
            "counter did not accumulate:\n{out}"
        );
    }

    /// A counter that only ever increments by one cannot express batch work, and
    /// a zero submission must not create a series that reads as "submitted here".
    #[test]
    fn submitted_batches_accumulate_by_amount_and_ignore_zero() {
        count_batches_submitted("treeSubmit", 3);
        count_batches_submitted("treeSubmit", 4);
        count_batches_submitted("treeZero", 0);
        let out = render();
        assert!(
            out.contains(
                r#"forester_batches_submitted_total{tree_pubkey="treeSubmit",tree_type="nullifier"} 7"#
            ),
            "counter did not add by amount:\n{out}"
        );
        assert!(
            !out.contains("treeZero"),
            "zero submission created a series:\n{out}"
        );
    }

    #[test]
    fn label_values_are_escaped() {
        assert_eq!(escape(r#"a"b\c"#), r#"a\"b\\c"#);
    }
}
