//! End-to-end BDD tests for the zone-transfer circuits (`zone_transact`). Each
//! scenario builds a zone-owned state transition over a chosen shape, proves it on
//! the prover server, and verifies against the committed verifying key:
//! `transfer_zone_<shape>` for the ed25519 (Solana-only) rail (vanilla Groth16) and
//! `transfer_p256_zone_<shape>` for the P256 rail (Groth16 with a BSB22 commitment).
//!
//! Requires a reachable prover server (started via `spawn_prover`) with the
//! `transfer_zone_<shape>.key` and `transfer_p256_zone_<shape>.key` proving keys
//! available.
//!
//! Run with: `cargo test -p rings-client --test zone_transfer_proving`

mod steps;
mod world;

// Shared with the transfer/merge/zone-authority runners; included by path since it
// lives at tests/.
#[path = "../test_indexer.rs"]
mod test_indexer;

use cucumber::World as _;

fn main() {
    futures::executor::block_on(
        world::ZoneTransferWorld::cucumber()
            .fail_on_skipped()
            .run_and_exit("tests/zone_transfer/features"),
    );
}
