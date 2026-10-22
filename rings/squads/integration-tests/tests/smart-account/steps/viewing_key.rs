//! `{word} has a viewing key account`: the backend creates the account with
//! freshly minted secrets. Vault senders get a smart-account owner, Ed25519
//! recipients a keypair owner; every vault-sender name shares one account.

use anyhow::{anyhow, ensure, Result};
use cucumber::given;
use solana_address::Address;
use zolana_client::Rpc;
use zolana_squads_interface::{
    constants::{OWNER_KIND_KEYPAIR, OWNER_KIND_SMART_ACCOUNT, VIEWING_KEY_STATE_ACTIVE},
    state::viewing_key_account::ViewingKeyAccount,
};

use crate::{
    fixture::{is_vault_sender, owner_identity, viewing_key_account_address},
    SquadsLifecycleWorld,
};

impl SquadsLifecycleWorld {
    pub(crate) fn load_viewing_key_account(&self, name: &str) -> Result<ViewingKeyAccount> {
        self.net
            .backend
            .load_viewing_key_account(Address::new_from_array(
                viewing_key_account_address(name).to_bytes(),
            ))
            .map_err(|e| anyhow!("load viewing key account of {name}: {e}"))
    }

    pub(crate) fn ensure_viewing_key_account(&mut self, name: &str) -> Result<()> {
        let address = Address::new_from_array(viewing_key_account_address(name).to_bytes());
        if self.net.base.rpc.get_account(address)?.is_some() {
            return Ok(());
        }
        let owner_kind = if is_vault_sender(name) {
            OWNER_KIND_SMART_ACCOUNT
        } else {
            OWNER_KIND_KEYPAIR
        };
        self.net
            .create_viewing_key_account(owner_identity(name), owner_kind)?;

        let account = self.load_viewing_key_account(name)?;
        ensure!(
            account.owner.to_bytes() == owner_identity(name),
            "viewing key account owner is {name}'s owner identity"
        );
        ensure!(
            account.owner_kind == owner_kind,
            "viewing key account owner kind"
        );
        ensure!(
            account.state == VIEWING_KEY_STATE_ACTIVE,
            "viewing key account is active"
        );
        Ok(())
    }
}

#[given(expr = "{word} has a viewing key account")]
fn has_viewing_key_account(world: &mut SquadsLifecycleWorld, name: String) {
    world
        .ensure_viewing_key_account(&name)
        .expect("create viewing key account");
}
