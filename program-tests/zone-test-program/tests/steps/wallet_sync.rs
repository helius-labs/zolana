//! `sync` step and UTXO-assertion steps. The `Wallet::sync` that decrypts indexed
//! UTXOs is separate from the assertions so features can sync and then check the
//! decrypted set explicitly. The World operations live in `world.rs`.

use cucumber::{then, when};

use crate::ZoneLifecycleWorld;

#[when(expr = "{word} syncs")]
fn syncs(world: &mut ZoneLifecycleWorld, name: String) {
    world.sync(&name).expect("sync");
}

#[then(expr = "{word}'s UTXOs match")]
fn utxos_match(world: &mut ZoneLifecycleWorld, name: String) {
    world.assert_utxos(&name).expect("assert UTXOs");
}

#[then(expr = "{word} has no UTXOs")]
fn has_no_utxos(world: &mut ZoneLifecycleWorld, name: String) {
    world.assert_no_utxos(&name).expect("sync");
}
