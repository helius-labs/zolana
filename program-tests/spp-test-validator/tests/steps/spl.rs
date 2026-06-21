//! `create_spl_interface` step: register one SPL asset for the scenario (mint +
//! interface + shared funding token account) and assert the interface was created.

use anyhow::{anyhow, Result};
use cucumber::given;
use solana_address::Address;
use solana_signer::Signer;
use zolana_test_utils::spl::{
    create_mint, create_spl_interface, create_token_account, ensure_asset_counter,
};
use zolana_test_utils::test_validator_asserts::assert_create_spl_interface;

use crate::world::SplAsset;
use crate::LifecycleWorld;

// SOL occupies asset id 1; the first registered SPL mint gets id 2.
const FIRST_SPL_ASSET_ID: u64 = 2;

impl LifecycleWorld {
    /// Register one SPL asset (idempotent): create a mint, ensure the asset counter,
    /// create + assert the shielded-pool interface (registry + vault), create a
    /// shared payer-owned funding token account, and add the mint to the registry so
    /// transfers can resolve its asset id.
    pub(crate) fn ensure_spl_asset(&mut self) -> Result<()> {
        if self.spl.is_some() {
            return Ok(());
        }
        let payer = self.payer.insecure_clone();
        let authority = self.authority.insecure_clone();

        let mint = create_mint(&self.rpc, &payer)?;
        ensure_asset_counter(&self.rpc, &authority)?;
        let (registry, vault) = create_spl_interface(&self.rpc, &authority, &mint)?;
        assert_create_spl_interface(
            &self.rpc,
            &registry,
            &vault,
            &mint,
            FIRST_SPL_ASSET_ID,
            FIRST_SPL_ASSET_ID + 1,
        )?;
        let user_token = create_token_account(&self.rpc, &payer, &mint, &payer.pubkey())?;

        self.assets
            .insert(FIRST_SPL_ASSET_ID, Address::new_from_array(mint.to_bytes()))
            .map_err(|e| anyhow!("register SPL asset: {e}"))?;
        self.spl = Some(SplAsset {
            mint,
            vault,
            user_token,
        });
        Ok(())
    }

    pub(crate) fn spl_asset(&self) -> Result<&SplAsset> {
        self.spl
            .as_ref()
            .ok_or_else(|| anyhow!("no SPL asset registered"))
    }
}

#[given(expr = "an SPL asset exists")]
fn spl_asset_exists(world: &mut LifecycleWorld) {
    world.ensure_spl_asset().expect("create SPL asset");
}
