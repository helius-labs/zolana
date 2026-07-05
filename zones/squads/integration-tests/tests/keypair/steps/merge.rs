//! Auto-merge (crank consolidation) steps.
//!
//! The backend's background crank scans every viewing key account and, when an
//! owner holds more than one spendable UTXO of an asset, proves and settles a
//! `merge_transact` that consolidates them into a single output tagged with the
//! owner's account view tag. These steps drive P256-owner accounts into a
//! fragmented state (multiple deposits, or a deposit plus an incoming transfer)
//! and assert the crank consolidates them, decrypted via the auditor key. The
//! crank keys the merge by the owner field (`from_owner_pk_field`), so it settles
//! P256-owner accounts without any owner signature.

use std::time::{Duration, Instant};

use anyhow::{anyhow, Result};
use cucumber::then;
use zolana_squads_client::{DecryptedUtxo, SOL_ASSET_ID};

use crate::world::SquadsLifecycleWorld;

/// How long to wait for the crank to consolidate an owner's fragmented balance.
/// Proving a merge and indexing its output leaf and nullifiers are async, and
/// staggered deposit indexing makes one logical consolidation take more than a
/// single merge round through a possibly-cold prover, so this polls generously.
const CONSOLIDATION_TIMEOUT: Duration = Duration::from_secs(120);

impl SquadsLifecycleWorld {
    /// Poll `getBalances` until the crank has consolidated `name`'s spendable UTXOs
    /// of `asset_id` into exactly ONE UTXO of `expected_amount`, returning it. The
    /// single-UTXO condition (not merely a matching total) confirms a merge actually
    /// happened rather than the fragments incidentally summing to `expected_amount`.
    pub(crate) fn wait_for_consolidated(
        &self,
        name: &str,
        asset_id: u64,
        expected_amount: u64,
    ) -> Result<DecryptedUtxo> {
        let started = Instant::now();
        loop {
            let utxos = self.sender_inputs(name, asset_id)?;
            if let Some(utxo) = utxos.first() {
                if utxos.len() == 1 && utxo.amount == expected_amount {
                    return Ok(*utxo);
                }
            }
            if started.elapsed() > CONSOLIDATION_TIMEOUT {
                let total: u64 = utxos.iter().map(|utxo| utxo.amount).sum();
                return Err(anyhow!(
                    "{name} not consolidated to one {expected_amount} lamport/token \
                     {asset_id} UTXO: {} spendable UTXOs totalling {total}",
                    utxos.len()
                ));
            }
            std::thread::sleep(Duration::from_millis(500));
        }
    }

    /// Assert the crank consolidated `name`'s SOL balance into a single UTXO of
    /// `expected_amount`.
    pub(crate) fn assert_consolidated_sol(&self, name: &str, expected_amount: u64) -> Result<()> {
        self.wait_for_consolidated(name, SOL_ASSET_ID, expected_amount)?;
        Ok(())
    }
}

#[then(expr = "the crank consolidates {word} into a {int} lamport SOL UTXO")]
fn crank_consolidates_sol(world: &mut SquadsLifecycleWorld, name: String, amount: i64) {
    world
        .assert_consolidated_sol(&name, amount as u64)
        .expect("crank consolidates SOL");
}
