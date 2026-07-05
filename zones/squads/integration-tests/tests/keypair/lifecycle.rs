//! Localnet + Photon BDD lifecycle tests for the Squads zone P256 (keypair-rail)
//! suite: `deposit` (tag 1) and `transact` withdrawal/transfer (tag 0), covering
//! the deposit -> transfer -> withdrawal lifecycle. Every spend routes through the
//! `zolana-squads-client` backend's two-call P256 rail (probe -> client signs
//! `sha256(private_tx_hash)` -> `requestTransact`); the async `execute_proposal`
//! rail is not exercised here (a background crank cannot produce the in-circuit
//! P256 owner signature a keypair spend requires).
//!
//! Each scenario runs against a freshly restarted `zolana test-validator` + Photon
//! indexer (the protocol config is a global singleton, so scenarios cannot share a
//! validator) and a persistent prover. The proofless `deposit` needs no prover; the
//! `transact` scenarios forward a real squads zone proof plus the SPP zone-rail
//! proof built by the backend. Viewing key accounts are created at runtime through
//! the backend; balances are decrypted with the auditor key via `getBalances`.

mod deposit_action;
mod fixture;
mod localnet;
mod steps;
mod world;

use cucumber::World as _;
pub use world::SquadsLifecycleWorld;

// Driven by the futures executor rather than tokio: the World and steps make
// blocking RPC/indexer calls (blocking reqwest), which panic if their internal
// runtime is dropped inside a tokio async context.
fn main() {
    futures::executor::block_on(
        SquadsLifecycleWorld::cucumber()
            .max_concurrent_scenarios(1)
            .fail_on_skipped()
            .run_and_exit("tests/keypair/features"),
    );
}
