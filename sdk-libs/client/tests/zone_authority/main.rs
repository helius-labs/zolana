//! End-to-end BDD tests for the zone-authority circuit (`zone_authority_transact`).
//! Each scenario builds a zone-owned state transition (owners do not sign), proves
//! it on the prover server, and verifies against the committed
//! `transfer_zone_authority_<shape>` verifying key (vanilla Groth16, no commitment).
//!
//! Requires a reachable prover server (started via `spawn_prover`) with the
//! `transfer_zone_authority_{1_1,2_2,3_3,4_4}.key` proving keys available.
//!
//! Run with: `cargo test -p rings-client --test zone_authority_proving`

mod steps;
mod world;

// Shared with the transfer/merge runners; included by path since it lives at tests/.
#[path = "../test_indexer.rs"]
mod test_indexer;

use cucumber::World as _;

fn main() {
    futures::executor::block_on(
        world::ZoneAuthorityWorld::cucumber()
            .fail_on_skipped()
            .run_and_exit("tests/zone_authority/features"),
    );
}
