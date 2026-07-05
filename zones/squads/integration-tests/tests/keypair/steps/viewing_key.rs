//! `viewing key account` step: create `name`'s viewing key account at runtime
//! through the backend's `requestCreateViewingKeyAccount`, then assert it exists,
//! is owned by the zone program, and is active.

use anyhow::{anyhow, Result};
use cucumber::given;
use solana_address::Address;
use zolana_client::Rpc;
use zolana_squads_interface::{
    constants::VIEWING_KEY_STATE_ACTIVE, state::viewing_key_account::ViewingKeyAccount,
    SQUADS_ZONE_PROGRAM_ID,
};
use zolana_test_utils::test_validator_asserts::to_address;

use crate::SquadsLifecycleWorld;

impl SquadsLifecycleWorld {
    pub(crate) fn create_viewing_key_account(&mut self, name: &str) -> Result<()> {
        let address = self.ensure_viewing_key_account(name)?;
        let account = self
            .rpc
            .get_account(to_address(&address))?
            .ok_or_else(|| anyhow!("viewing key account missing for {name}"))?;
        assert_eq!(
            account.owner,
            Address::new_from_array(SQUADS_ZONE_PROGRAM_ID),
            "viewing key account is owned by the zone program"
        );
        let decoded = ViewingKeyAccount::deserialize(&account.data)
            .map_err(|e| anyhow!("decode viewing key account: {e}"))?;
        assert_eq!(
            decoded.discriminator,
            ViewingKeyAccount::DISCRIMINATOR,
            "viewing key account discriminator"
        );
        assert_eq!(
            decoded.state, VIEWING_KEY_STATE_ACTIVE,
            "viewing key account is active"
        );
        Ok(())
    }
}

#[given(expr = "{word} has a viewing key account")]
fn has_viewing_key_account(world: &mut SquadsLifecycleWorld, name: String) {
    world
        .create_viewing_key_account(&name)
        .expect("create viewing key account");
}
