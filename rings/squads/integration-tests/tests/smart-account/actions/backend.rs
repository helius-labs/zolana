//! Backend `getBalances` assertion steps.
//!
//! These prove the auditor-key model: the backend recovers each account's shared
//! viewing key from the auditor ciphertext and decrypts the account's balances,
//! without any user viewing/nullifier secret. Each viewing key account was created
//! at runtime with its shared key encrypted to the ring's auditor key (which the
//! backend holds), so a balance the backend reports here is decrypted purely from
//! on-chain data plus the auditor secret.

use std::time::{Duration, Instant};

use anyhow::{ensure, Result};
use zolana_squads_client::GetBalancesRequest;

use crate::harness::SquadsSmartAccountHarness;

/// How long to poll the backend for the expected balance. Settlement and Photon
/// indexing are async, so a freshly settled change output takes a moment to surface.
const BALANCE_POLL_TIMEOUT: Duration = Duration::from_secs(30);

impl SquadsSmartAccountHarness {
    /// Assert the backend, using only the auditor secret, decrypts `name`'s balance
    /// for `asset_id` as `expected`. Polls until the balance matches or the timeout
    /// elapses (async settlement + indexing lag), failing with the last read.
    pub(crate) fn assert_backend_balance(
        &self,
        name: &str,
        asset_id: u64,
        expected: u64,
    ) -> Result<()> {
        let viewing_key_account = self.viewing_key_account_address(name);
        let started = Instant::now();
        let amount = loop {
            let response = self
                .backend
                .get_balances(GetBalancesRequest {
                    viewing_key_account,
                    skip_utxos: false,
                    signature: [0u8; 64],
                })
                .map_err(|e| anyhow::anyhow!("backend get_balances: {e}"))?;
            let amount = response
                .balances
                .iter()
                .find(|balance| balance.asset_id == asset_id)
                .map(|balance| balance.amount)
                .unwrap_or(0);
            if amount == expected || started.elapsed() > BALANCE_POLL_TIMEOUT {
                break amount;
            }
            std::thread::sleep(Duration::from_millis(500));
        };
        ensure!(
            amount == expected,
            "backend decrypted {amount} for asset {asset_id}, expected {expected}"
        );
        Ok(())
    }
}
