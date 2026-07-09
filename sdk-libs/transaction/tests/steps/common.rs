use cucumber::given;
use rings_keypair::ShieldedKeypair;

use crate::TransactionWorld;

#[given(expr = "a shielded keypair {string}")]
fn shielded_keypair(world: &mut TransactionWorld, name: String) {
    world.keypairs.insert(name, ShieldedKeypair::new().unwrap());
}
