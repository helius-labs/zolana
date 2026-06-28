//! Localnet + Photon BDD lifecycle tests for the CPI-forwarding fixture.
//!
//! Each scenario runs against a freshly restarted `solana-test-validator` + Photon
//! indexer (the protocol config is a global singleton, so scenarios cannot share a
//! validator) with the CPI-forwarding fixture program loaded alongside the shielded
//! pool. The prover server is started once and persists across scenarios.
//!
//! The scenario shields SOL into a sender (eddsa rail), spends it through a real
//! program-governed `transact` wrapped by the fixture program (which signs its
//! `CPI_SIGNER_PDA`), and asserts a recipient wallet discovers the program-governed
//! output UTXO via `Wallet::sync` against real Photon.

mod actor;
mod deposit_action;
mod localnet;
mod steps;
mod world;

use cucumber::World as _;
pub use world::CpiLifecycleWorld;

// Driven by the futures executor rather than tokio: the World and steps make
// blocking RPC/indexer calls (blocking reqwest), which panic if their internal
// runtime is dropped inside a tokio async context.
fn main() {
    futures::executor::block_on(
        CpiLifecycleWorld::cucumber()
            .max_concurrent_scenarios(1)
            .fail_on_skipped()
            .run_and_exit("tests/features"),
    );
}
