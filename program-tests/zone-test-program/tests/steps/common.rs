//! Background setup steps: the precondition marker, the eddsa-rail opt-in, and
//! SPL asset registration.

use anyhow::Result;
use cucumber::given;

use crate::{actor::Actor, ZoneLifecycleWorld};

impl ZoneLifecycleWorld {
    /// Create `name` as an eddsa-rail actor whose owner is the payer's ed25519 key,
    /// so the payer's transaction signature satisfies the owner check (the actor pays
    /// and signs its own spends; the payer is its `solana_signer`). Its UTXOs take the
    /// eddsa rail.
    pub(crate) fn make_eddsa_actor(&mut self, name: &str) -> Result<()> {
        let actor = Actor::eddsa(self.payer.insecure_clone())?;
        self.actors.insert(name.to_string(), actor);
        Ok(())
    }
}

#[given(expr = "a fresh shielded pool")]
fn fresh_pool(_world: &mut ZoneLifecycleWorld) {
    // `ZoneLifecycleWorld::new` already restarted the validator + Photon, started
    // the (persistent) prover, loaded the zone-test fixture, and created the
    // protocol config and a tree. This step exists so features can name the
    // precondition.
}

#[given(expr = "{word} with shielded solana keypair")]
fn shielded_solana_keypair(world: &mut ZoneLifecycleWorld, name: String) {
    world.make_eddsa_actor(&name).expect("create eddsa actor");
}

#[given(expr = "an SPL asset exists")]
fn spl_asset_exists(world: &mut ZoneLifecycleWorld) {
    world.ensure_spl_asset().expect("create SPL asset");
}
