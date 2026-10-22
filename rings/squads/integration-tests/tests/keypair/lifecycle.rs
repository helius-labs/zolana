//! Localnet + Photon BDD lifecycle of the Squads ring on the Ed25519 keypair
//! rail: deposits, the backend's probe -> sign `transact_message_hash(private_tx_hash, external_data_hash)` ->
//! `requestTransact` spends, and crank consolidation. Each scenario restarts
//! the validator + Photon (the protocol config is a singleton) and shares one
//! prover.

mod fixture;
mod steps;
mod world;

use cucumber::World as _;
pub use world::SquadsLifecycleWorld;

// The steps make blocking RPC calls, which panic inside a tokio runtime.
fn main() {
    futures::executor::block_on(
        SquadsLifecycleWorld::cucumber()
            .max_concurrent_scenarios(1)
            .fail_on_skipped()
            .run_and_exit("tests/keypair/features"),
    );
}
