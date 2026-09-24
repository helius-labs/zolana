use super::loader::load_cache_mut;
use pinocchio::{
    account::RefMut, address::address_eq, error::ProgramError, AccountView, ProgramResult,
};
use zolana_interface::{error::ShieldedPoolError, state::CacheAccount};

/// A cache account validated once for a whole instruction: the writer holds the
/// stored `write_authority` and the cache has not expired. The account parser
/// has already required the writer to sign. Slots are checked and written
/// through it, so a multi-output write validates the account once rather than
/// once per output.
pub(crate) struct CacheWrite<'a> {
    state: RefMut<'a, CacheAccount>,
    address: [u8; 32],
}

impl<'a> CacheWrite<'a> {
    pub fn load(
        account: &'a mut AccountView,
        writer: &AccountView,
        now: i64,
    ) -> Result<Self, ProgramError> {
        let address = account.address().to_bytes();
        let state = load_cache_mut(account)?;
        if !address_eq(writer.address(), &state.write_authority) {
            return Err(ShieldedPoolError::CacheWriteAuthorityMismatch.into());
        }
        if now >= state.expiry_unix_ts() {
            return Err(ShieldedPoolError::CacheExpired.into());
        }
        Ok(Self { state, address })
    }

    pub fn state(&self) -> &CacheAccount {
        &self.state
    }

    pub fn address(&self) -> &[u8; 32] {
        &self.address
    }

    pub fn check_slot(&self, slot: u8) -> ProgramResult {
        self.state
            .utxo_hashes
            .get(usize::from(slot))
            .ok_or(ShieldedPoolError::InvalidCacheSlot)?;
        Ok(())
    }

    /// A cache belongs to one tree, so it only accepts outputs appended to it.
    pub fn check_output_tree(&self, output_tree_id: u16) -> ProgramResult {
        if output_tree_id != u16::from_le_bytes(self.state.tree_id) {
            return Err(ShieldedPoolError::CacheTreeMismatch.into());
        }
        Ok(())
    }

    pub fn write(&mut self, slot: u8, utxo_hash: &[u8; 32]) -> ProgramResult {
        let entry = self
            .state
            .utxo_hashes
            .get_mut(usize::from(slot))
            .ok_or(ShieldedPoolError::InvalidCacheSlot)?;
        *entry = *utxo_hash;
        Ok(())
    }
}
