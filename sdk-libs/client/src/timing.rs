//! Opt-in phase timing, printed to stderr when `ZOLANA_TIMING` is set.
//!
//! Lives in the client crate because the interesting
//! question spans crates: a transfer's cost splits across syncing, fetching
//! proofs, and proving, and attributing it needs the same clock on all of them.

use std::{
    sync::OnceLock,
    time::{Duration, Instant},
};

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
