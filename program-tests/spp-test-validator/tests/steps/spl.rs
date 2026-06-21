//! `create_spl_interface` step: register SPL assets for the scenario (mint +
//! interface + shared funding token account) and assert the interface was created.

use anyhow::{anyhow, Result};
use cucumber::given;
use solana_address::Address;
use solana_signer::Signer;
use zolana_test_utils::{
    spl::{create_mint, create_spl_interface, create_token_account, ensure_asset_counter},
    test_validator_asserts::assert_create_spl_interface,
};

use crate::{world::SplAsset, LifecycleWorld};

// SOL occupies asset id 1; the first registered SPL mint gets id 2.
const FIRST_SPL_ASSET_ID: u64 = 2;

impl LifecycleWorld {
    /// Register `count` SPL assets, extending `self.spls` until it holds at least
    /// `count` (idempotent). Each registration creates a mint, ensures the asset
    /// counter, creates + asserts the shielded-pool interface (registry + vault),
    /// creates a shared payer-owned funding token account, and adds the mint to the
    /// asset registry under the next asset id so transfers can resolve it.
    pub(crate) fn ensure_spl_assets(&mut self, count: usize) -> Result<()> {
        let payer = self.payer.insecure_clone();
        let authority = self.authority.insecure_clone();

        while self.spls.len() < count {
            let asset_id = FIRST_SPL_ASSET_ID + self.spls.len() as u64;

            let mint = create_mint(&self.rpc, &payer)?;
            ensure_asset_counter(&self.rpc, &authority)?;
            let (registry, vault) = create_spl_interface(&self.rpc, &authority, &mint)?;
            assert_create_spl_interface(
                &self.rpc,
                &registry,
                &vault,
                &mint,
                asset_id,
                asset_id + 1,
            )?;
            let user_token = create_token_account(&self.rpc, &payer, &mint, &payer.pubkey())?;

            self.assets
                .insert(asset_id, Address::new_from_array(mint.to_bytes()))
                .map_err(|e| anyhow!("register SPL asset: {e}"))?;
            self.spls.push(SplAsset {
                mint,
                vault,
                user_token,
            });
        }
        Ok(())
    }

    /// Register one SPL asset (idempotent), used by single-asset features.
    pub(crate) fn ensure_spl_asset(&mut self) -> Result<()> {
        self.ensure_spl_assets(1)
    }

    pub(crate) fn spl_asset(&self) -> Result<&SplAsset> {
        self.spls
            .first()
            .ok_or_else(|| anyhow!("no SPL asset registered"))
    }
}

#[given(expr = "an SPL asset exists")]
fn spl_asset_exists(world: &mut LifecycleWorld) {
    world.ensure_spl_asset().expect("create SPL asset");
}
