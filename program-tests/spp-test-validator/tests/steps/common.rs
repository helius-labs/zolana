//! Background setup steps: the precondition marker and the eddsa-rail opt-in.

use anyhow::Result;
use cucumber::given;
use zolana_keypair::{ShieldedKeypair, ViewingKey};

use crate::{actor::Actor, LifecycleWorld};

impl LifecycleWorld {
    /// Create `name` as an eddsa-rail actor whose owner is the payer's ed25519 key,
    /// so the payer's transaction signature satisfies the owner check (the transact
    /// builder's only signer is the fee payer). Its UTXOs take the eddsa rail.
    pub(crate) fn make_eddsa_actor(&mut self, name: &str) -> Result<()> {
        let seed: [u8; 32] = self.payer.to_bytes()[..32]
            .try_into()
            .expect("ed25519 seed is the first 32 bytes");
        let keypair = ShieldedKeypair::from_ed25519(&seed, ViewingKey::new())?;
        self.actors
            .insert(name.to_string(), Actor::with_keypair(keypair)?);
        Ok(())
    }
}

#[given(expr = "a fresh shielded pool")]
fn fresh_pool(_world: &mut LifecycleWorld) {
    // `LifecycleWorld::new` already restarted the validator + Photon, started the
    // (persistent) prover, and created the protocol config and a tree. This step
    // exists so features can name the precondition.
}

#[given(expr = "{word} with shielded solana keypair")]
fn shielded_solana_keypair(world: &mut LifecycleWorld, name: String) {
    world.make_eddsa_actor(&name).expect("create eddsa actor");
}
