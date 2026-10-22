//! Localnet + Photon BDD lifecycle of the Squads ring owned by a Squads smart
//! account. The proposer vault deposits and creates proposals through
//! `executeTransactionSyncV2`; sync spends are built by the backend on the
//! signatureless ring-authority rail and proposals are settled by its crank.
//! Each scenario restarts the validator + Photon and shares one prover.

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
            .run_and_exit("tests/smart-account/features"),
    );
}
