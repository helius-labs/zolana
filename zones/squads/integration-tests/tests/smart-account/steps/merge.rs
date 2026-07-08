//! Auto-merge assertion step.
//!
//! The background settlement crank consolidates any owner's fragmented spendable
//! UTXOs of an asset into a single UTXO tagged with the owner's account view tag.
//! This step polls the backend until that consolidation has happened, asserting the
//! account ends with exactly one UTXO of the expected summed amount.

use cucumber::then;
use zolana_squads_client::SOL_ASSET_ID;

use crate::world::SquadsLifecycleWorld;

#[then(expr = "{word} consolidates into a {int} lamport SOL UTXO")]
fn consolidates_sol(world: &mut SquadsLifecycleWorld, name: String, amount: i64) {
    world
        .wait_for_consolidated(&name, SOL_ASSET_ID, amount as u64)
        .expect("consolidate SOL UTXO");
}
