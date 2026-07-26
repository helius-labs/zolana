//! Shared support library for the shielded-pool integration test suite.
//!
//! Integration-test binaries import initialized environments, fixtures, and
//! builders from [`support`] instead of compiling ad hoc `#[path]` modules per
//! binary. Generic, program-agnostic behavior lives in `zolana-test-utils`,
//! `zolana-program-test`, and the Mollusk harness; this crate owns only
//! shielded-pool-specific support (initialized environments, fixture snapshots,
//! and builders).

pub mod support;
