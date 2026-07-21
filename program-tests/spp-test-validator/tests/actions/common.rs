//! Background setup steps: the precondition marker and the eddsa-rail opt-in.

use anyhow::Result;

use crate::{actor::Actor, LifecycleHarness};

impl LifecycleHarness {
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
