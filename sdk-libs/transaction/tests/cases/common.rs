use zolana_keypair::ShieldedKeypair;

use crate::TransactionWorld;

pub(crate) fn shielded_keypair(world: &mut TransactionWorld, name: String) {
    world.keypairs.insert(name, ShieldedKeypair::new().unwrap());
}
