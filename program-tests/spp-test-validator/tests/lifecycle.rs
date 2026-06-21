//! Localnet + Photon BDD lifecycle tests for the shielded pool.
//!
//! Each scenario runs against a freshly restarted `solana-test-validator` + Photon
//! indexer (the protocol config is a global singleton, so scenarios cannot share a
//! validator). The prover server is started once and persists across scenarios.
//!
//! Each scenario indexes a UTXO through Photon, decrypts it with `Wallet::sync`,
//! and spends it (consuming its nullifier). The decrypted set is checked against
//! the expected set with a full-struct `assert_eq` over `WalletUtxo`, tracked in
//! the World.

mod actor;
mod deposit_action;
mod localnet;
mod steps;
mod world;

pub use world::LifecycleWorld;

use cucumber::World as _;

// Driven by the futures executor rather than tokio: the World and steps make
// blocking RPC/indexer calls (blocking reqwest), which panic if their internal
// runtime is dropped inside a tokio async context.
fn main() {
    futures::executor::block_on(
        LifecycleWorld::cucumber()
            .max_concurrent_scenarios(1)
            .fail_on_skipped()
            .run_and_exit("tests/features"),
    );
}
