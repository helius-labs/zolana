//! Localnet + Photon BDD lifecycle tests for the Squads zone driven by a Squads
//! SMART ACCOUNT, routed through the mock backend `zolana-squads-client`.
//!
//! A real smart-account vault is the executing party / UTXO owner: it executes
//! `deposit` (tag 1, client-built) and creates + owns the async proposal
//! (`create_proposal`, tag 11, wrapped in `executeTransactionSyncV2`). Everything
//! else flows through the backend, which holds the auditor key: viewing key accounts
//! are created at runtime (`request_create_viewing_key_account`, random secrets),
//! sync transfer / withdrawal are built by `request_transact` (smart-account rail),
//! async proposals are settled by the backend's autonomous background crank, and all
//! balances are read via `get_balances`. The zone `owner` identity is the vault's
//! pk-field-hash (`owner_pk_field`).
//!
//! Each scenario runs against a freshly restarted `zolana test-validator` + Photon
//! indexer (the protocol config is a global singleton, so scenarios cannot share a
//! validator) and a persistent prover. The proof-bearing paths (VKA creation, sync
//! `transact`, async settlement) forward real squads zone + SPP zone-rail proofs.
//! Deposits assert the full state transition through SPP; transfers and withdrawals
//! assert the shielded balances via the backend plus the on-chain fund movement.

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
            .run_and_exit("tests/smart-account/features"),
    );
}
