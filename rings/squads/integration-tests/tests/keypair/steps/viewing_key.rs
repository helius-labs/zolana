//! `{word} has a viewing key account`: the backend creates the account with
//! freshly minted secrets, then the step checks the on-chain account.

use anyhow::{anyhow, ensure, Result};
use cucumber::given;
use solana_address::Address;
use solana_pubkey::Pubkey;
use zolana_client::Rpc;
use zolana_squads_interface::{
    constants::{OWNER_KIND_KEYPAIR, VIEWING_KEY_STATE_ACTIVE},
    state::viewing_key_account::ViewingKeyAccount,
    SQUADS_RING_PROGRAM_ID,
};

use crate::{fixture::owner_keypair, SquadsLifecycleWorld};

impl SquadsLifecycleWorld {
    pub(crate) fn ensure_viewing_key_account(&mut self, name: &str) -> Result<Pubkey> {
        let owner = owner_keypair(name);
        if self.viewing_key_accounts.contains(name) {
            return Ok(owner.viewing_key_account());
        }
        let address = self
            .net
            .create_viewing_key_account(owner.owner_identity(), OWNER_KIND_KEYPAIR)?;
        self.viewing_key_accounts.insert(name.to_string());
        Ok(address)
    }

    pub(crate) fn load_viewing_key_account(&self, name: &str) -> Result<ViewingKeyAccount> {
        let address = owner_keypair(name).viewing_key_account();
        self.net
            .backend
            .load_viewing_key_account(Address::new_from_array(address.to_bytes()))
            .map_err(|e| anyhow!("load viewing key account of {name}: {e}"))
    }

    fn create_and_check_viewing_key_account(&mut self, name: &str) -> Result<()> {
        let address = self.ensure_viewing_key_account(name)?;
        let account = self
            .net
            .base
            .rpc
            .get_account(Address::new_from_array(address.to_bytes()))?
            .ok_or_else(|| anyhow!("viewing key account missing for {name}"))?;
        ensure!(
            account.owner == Address::new_from_array(SQUADS_RING_PROGRAM_ID),
            "viewing key account is owned by the ring program"
        );
        let decoded = ViewingKeyAccount::deserialize(&account.data)
            .map_err(|e| anyhow!("decode viewing key account: {e}"))?;
        ensure!(
            decoded.discriminator == ViewingKeyAccount::DISCRIMINATOR,
            "viewing key account discriminator"
        );
        ensure!(
            decoded.owner.to_bytes() == owner_keypair(name).owner_identity(),
            "viewing key account owner is the Ed25519 owner identity"
        );
        ensure!(
            decoded.owner_kind == OWNER_KIND_KEYPAIR,
            "viewing key account owner kind"
        );
        ensure!(
            decoded.state == VIEWING_KEY_STATE_ACTIVE,
            "viewing key account is active"
        );
        Ok(())
    }
}

#[given(expr = "{word} has a viewing key account")]
fn has_viewing_key_account(world: &mut SquadsLifecycleWorld, name: String) {
    world
        .create_and_check_viewing_key_account(&name)
        .expect("create viewing key account");
}
