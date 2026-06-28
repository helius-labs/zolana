//! `sync` step and the UTXO-assertion step. The `Wallet::sync` that decrypts
//! indexed UTXOs is separate from the assertion so features can sync and then check
//! the decrypted set explicitly. The World operations live in `world.rs`.

use cucumber::{then, when};

use crate::CpiLifecycleWorld;

#[when(expr = "{word} syncs")]
fn syncs(world: &mut CpiLifecycleWorld, name: String) {
    world.sync(&name).expect("sync");
}

#[then(expr = "{word}'s UTXOs match")]
fn utxos_match(world: &mut CpiLifecycleWorld, name: String) {
    world.assert_utxos(&name).expect("assert UTXOs");
}
