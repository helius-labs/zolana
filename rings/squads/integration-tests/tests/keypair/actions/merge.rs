//! The backend crank scans every viewing key account and, when an owner
//! holds more than one spendable UTXO of an asset, proves and settles a
//! `merge_transact` that consolidates them into one output tagged with the
//! owner's account view tag. The crank keys the merge by the owner field, so
//! it settles P256-owner accounts without any owner signature.

use std::time::{Duration, Instant};

use anyhow::{anyhow, Result};
use zolana_squads_client::{DecryptedUtxo, SOL_ASSET_ID};

use crate::harness::SquadsKeypairHarness;

/// Proving and indexing are async, and staggered deposit indexing can push
/// one consolidation past a single merge round through a possibly cold
/// prover, so the poll is generous.
const CONSOLIDATION_TIMEOUT: Duration = Duration::from_secs(120);

impl SquadsKeypairHarness {
    /// Exactly one UTXO proves a merge happened. Fragments that sum to the
    /// total would otherwise pass.
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

    pub(crate) fn assert_consolidated_sol(&self, name: &str, expected_amount: u64) -> Result<()> {
        self.wait_for_consolidated(name, SOL_ASSET_ID, expected_amount)?;
        Ok(())
    }
}
