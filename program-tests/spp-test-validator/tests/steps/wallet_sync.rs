//! `sync` step and UTXO-assertion steps. The `Wallet::sync` that decrypts indexed
//! UTXOs is separate from the assertions so features can sync and then check the
//! decrypted set explicitly.

use anyhow::Result;
use cucumber::{then, when};
use zolana_transaction::{Utxo, DEFAULT_TAG_WINDOW};

use crate::{localnet::ZERO, LifecycleWorld};

impl LifecycleWorld {
    /// Sync an actor's wallet from every indexed transfer (decryption), and make
    /// newly decrypted, unspent UTXOs spendable. No assertions.
    pub(crate) fn sync(&mut self, name: &str) -> Result<()> {
        self.ensure_actor(name)?;
        let indexed = self.indexed.clone();
        let assets = self.assets.clone();
        let actor = self.actor_mut(name);
        actor
            .wallet
            .sync(&indexed, &assets, 0, DEFAULT_TAG_WINDOW)?;

        let nullifier_pk = actor.keypair.nullifier_key.pubkey()?;
        let mut spendable_hashes: Vec<[u8; 32]> = Vec::new();
        for utxo in &actor.spendable {
            spendable_hashes.push(utxo.hash(&nullifier_pk, &ZERO, &ZERO)?);
        }
        let newly_spendable: Vec<Utxo> = actor
            .wallet
            .utxos
            .iter()
            .filter(|w| !w.spent && !spendable_hashes.contains(&w.output_context.hash))
            .map(|w| w.utxo.clone())
            .collect();
        actor.spendable.extend(newly_spendable);
        Ok(())
    }

    /// Full-struct assert that the actor's synced wallet holds exactly the UTXOs it
    /// is expected to have decrypted (with `spent` flags). Run `sync` first.
    pub(crate) fn assert_utxos(&self, name: &str) -> Result<()> {
        let actor = self.actor(name);
        let mut actual = actor.wallet.utxos.clone();
        let mut expected = actor.expected.clone();
        actual.sort_by_key(|u| u.output_context.hash);
        expected.sort_by_key(|u| u.output_context.hash);
        assert_eq!(
            actual, expected,
            "synced UTXOs for {name} do not match expected"
        );
        Ok(())
    }

    /// Sync and assert the actor decrypts nothing (view-tag isolation).
    pub(crate) fn assert_no_utxos(&mut self, name: &str) -> Result<()> {
        self.ensure_actor(name)?;
        let indexed = self.indexed.clone();
        let assets = self.assets.clone();
        let actor = self.actor_mut(name);
        actor
            .wallet
            .sync(&indexed, &assets, 0, DEFAULT_TAG_WINDOW)?;
        assert!(
            actor.wallet.utxos.is_empty(),
            "{name} should not decrypt any UTXOs but found {}",
            actor.wallet.utxos.len()
        );
        Ok(())
    }
}

#[when(expr = "{word} syncs")]
fn syncs(world: &mut LifecycleWorld, name: String) {
    world.sync(&name).expect("sync");
}

#[then(expr = "{word}'s UTXOs match")]
fn utxos_match(world: &mut LifecycleWorld, name: String) {
    world.assert_utxos(&name).expect("assert UTXOs");
}

#[then(expr = "{word} has no UTXOs")]
fn has_no_utxos(world: &mut LifecycleWorld, name: String) {
    world.assert_no_utxos(&name).expect("sync");
}
