//! Opt-in phase timing, printed to stderr when `ZOLANA_TIMING` is set.
//!
//! Lives in the client crate because the interesting
//! question spans crates: a transfer's cost splits across syncing, fetching
//! proofs, and proving, and attributing it needs the same clock on all of them.

use std::{
    sync::{Arc, OnceLock},
    time::{Duration, Instant},
};

use reqwest::header::HeaderMap;
use serde::Deserialize;

fn enabled() -> bool {
    static ON: OnceLock<bool> = OnceLock::new();
    *ON.get_or_init(|| std::env::var_os("ZOLANA_TIMING").is_some())
}

/// Emit a scalar observation (counts, sizes) alongside the phase timings.
pub fn note(round: usize, key: &str, value: usize) {
    if enabled() {
        eprintln!("timing round={round} {key}={value}");
    }
}

/// Times from construction to drop, so `?` early-returns still report.
pub struct Phase {
    name: &'static str,
    round: usize,
    started: Instant,
}

impl Phase {
    pub fn start(name: &'static str, round: usize) -> Self {
        Self {
            name,
            round,
            started: Instant::now(),
        }
    }
}

impl Drop for Phase {
    fn drop(&mut self) {
        if enabled() {
            let ms = self.started.elapsed().max(Duration::ZERO).as_millis();
            eprintln!("timing round={} phase={} ms={}", self.round, self.name, ms);
        }
    }
}

pub(crate) const PROVER_TIMING_HEADER: &str = "X-Prover-Timing";

#[derive(Clone, Debug)]
pub struct ProverTiming {
    /// Excludes the query, where an API key may sit.
    pub path: String,
    pub status: u16,
    /// Send to last response byte of the final attempt.
    pub elapsed: Duration,
    /// Empty unless the prover runs with `PROVER_REQUEST_TIMING=true`.
    pub spans: Vec<ProverSpan>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ProverSpan {
    pub name: String,
    pub start_ms: f64,
    pub duration_ms: f64,
    /// False for a span still open when the response left.
    pub complete: bool,
}

pub type ProverTimingSink = Arc<dyn Fn(ProverTiming) + Send + Sync>;

/// A malformed header reads as no spans, since timing never fails a proof.
pub(crate) fn prover_spans(headers: &HeaderMap) -> Vec<ProverSpan> {
    headers
        .get(PROVER_TIMING_HEADER)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| serde_json::from_str(value).ok())
        .unwrap_or_default()
}

pub(crate) fn emit(sink: Option<&ProverTimingSink>, timing: impl FnOnce() -> ProverTiming) {
    if let Some(sink) = sink {
        sink(timing());
    }
}

#[cfg(test)]
mod tests {
    use reqwest::header::HeaderValue;

    use super::*;

    #[test]
    fn a_malformed_timing_header_reads_as_no_spans() {
        let mut headers = HeaderMap::new();
        assert!(prover_spans(&headers).is_empty());
        headers.insert(PROVER_TIMING_HEADER, HeaderValue::from_static("not json"));
        assert!(prover_spans(&headers).is_empty());
    }
}
