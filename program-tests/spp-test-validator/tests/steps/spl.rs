//! `create_spl_interface` step: register SPL assets for the scenario (mint +
//! interface + shared funding token account) and assert the interface was created.

use anyhow::{anyhow, Result};
use cucumber::given;
use solana_address::Address;
use solana_signer::Signer;
use zolana_client::Rpc;
use zolana_interface::{
    instruction::{CreateAssetCounter, CreateSplInterface},
    pda,
};
use zolana_test_utils::{
    smart_account::execute_sync_ix,
    spl::{create_mint, create_token_account},
    test_validator_asserts::assert_create_spl_interface,
};

use crate::{localnet::send_transaction, world::SplAsset, LifecycleWorld};

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
        let protocol_vault = self.protocol_vault;
        let protocol_settings = self.protocol_settings;

        while self.spls.len() < count {
            let asset_id = FIRST_SPL_ASSET_ID + self.spls.len() as u64;

            let mint = create_mint(&self.rpc, &payer)?;

            // Both CreateAssetCounter and CreateSplInterface check protocol_authority
            // in ProtocolConfig, which is now the protocol vault PDA. Wrap each in
            // execute_sync_ix so the vault signs via the Squads CPI mechanism.
            let counter_addr = Address::new_from_array(pda::spl_asset_counter().to_bytes());
            if self.rpc.get_account(counter_addr)?.is_none() {
                let ix = CreateAssetCounter {
                    authority: protocol_vault,
                }
                .instruction();
                let sync_ix = execute_sync_ix(&protocol_settings, 0, &[authority.pubkey()], &[ix]);
                send_transaction(
                    &mut self.rpc,
                    &[sync_ix],
                    &payer.pubkey(),
                    &[&payer, &authority],
                )?;
            }

            let ix = CreateSplInterface {
                authority: protocol_vault,
                mint,
            }
            .instruction();
            let sync_ix = execute_sync_ix(&protocol_settings, 0, &[authority.pubkey()], &[ix]);
            send_transaction(
                &mut self.rpc,
                &[sync_ix],
                &payer.pubkey(),
                &[&payer, &authority],
            )?;
            let registry = pda::spl_asset_registry(&mint);
            let vault = pda::spl_asset_vault(&mint);

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
