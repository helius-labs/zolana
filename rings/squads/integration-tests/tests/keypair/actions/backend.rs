//! The backend recovers each account's shared viewing key from the auditor
//! ciphertext and decrypts balances without any user viewing or nullifier
//! secret. Each runtime-created viewing key account publishes its shared key
//! encrypted to the ring's auditor key, so a balance reported here comes
//! purely from on-chain data plus the auditor secret.

use std::time::{Duration, Instant};

use anyhow::{ensure, Result};
use solana_address::Address;
use zolana_squads_client::GetBalancesRequest;

use crate::{fixture::viewing_key_account_address, harness::SquadsKeypairHarness};

/// Settlement and Photon indexing are async, so a freshly settled output
/// takes time to surface.
const BALANCE_POLL_TIMEOUT: Duration = Duration::from_secs(30);

impl SquadsKeypairHarness {
    pub(crate) fn assert_backend_balance(
        &self,
        name: &str,
        asset_id: u64,
        expected: u64,
    ) -> Result<()> {
        let viewing_key_account =
            Address::new_from_array(viewing_key_account_address(name).to_bytes());
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
