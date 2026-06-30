//! Localnet + Photon BDD lifecycle tests for the policy-zone fixture.
//!
//! Each scenario runs against a freshly restarted `solana-test-validator` + Photon
//! indexer (the protocol config is a global singleton, so scenarios cannot share a
//! validator) with the zone-test fixture program loaded alongside the shielded
//! pool. The prover server is started once and persists across scenarios.

mod actor;
mod localnet;
mod steps;
mod support;
mod world;

use cucumber::World as _;
pub use world::ZoneLifecycleWorld;

// Driven by the futures executor rather than tokio: the World and steps make
// blocking RPC/indexer calls (blocking reqwest), which panic if their internal
// runtime is dropped inside a tokio async context.
fn main() {
    futures::executor::block_on(
        ZoneLifecycleWorld::cucumber()
            .max_concurrent_scenarios(1)
            .fail_on_skipped()
            .run_and_exit("tests/features"),
    );
}
