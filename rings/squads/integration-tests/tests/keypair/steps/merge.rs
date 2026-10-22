//! Crank consolidation: the backend crank merges an owner's fragmented UTXOs of
//! one asset into a single output without an owner signature.

use cucumber::then;
use squads_ring_tests::localnet::SOL_ASSET_ID;

use crate::{fixture::viewing_key_account_address, world::SquadsLifecycleWorld};

#[then(expr = "the crank consolidates {word} into a {int} lamport SOL UTXO")]
fn crank_consolidates_sol(world: &mut SquadsLifecycleWorld, name: String, amount: u64) {
    world
        .net
        .wait_for_consolidated(viewing_key_account_address(&name), SOL_ASSET_ID, amount)
        .expect("crank consolidates SOL");
}
