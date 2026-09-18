use crate::instructions::cache::loader::load_cache_mut;
use pinocchio::{
    account::RefMut, address::address_eq, error::ProgramError, AccountView, ProgramResult,
};
use zolana_interface::{error::ShieldedPoolError, state::CacheAccount, tree_slot::tree_id_field};

pub(crate) struct CacheSlot<'a> {
    state: RefMut<'a, CacheAccount>,
    address: [u8; 32],
    slot: u8,
}

impl<'a> CacheSlot<'a> {
    pub fn load_and_validate_optional(
        cache: Option<(&'a mut AccountView, u8)>,
        payer: &AccountView,
        expected_identity: Option<&[u8; 32]>,
        now: i64,
    ) -> Result<Option<Self>, ProgramError> {
        let Some((account, slot)) = cache else {
            return Ok(None);
        };
        let address = account.address().to_bytes();
        let state = load_cache_mut(account)?;
        if !payer.is_signer() {
            return Err(ProgramError::MissingRequiredSignature);
        }
        if !address_eq(payer.address(), &state.write_authority) {
            return Err(ShieldedPoolError::CacheWriteAuthorityMismatch.into());
        }
        if let Some(expected) = expected_identity {
            if state.owner_identity != *expected {
                return Err(ShieldedPoolError::CacheOwnerMismatch.into());
            }
        }
        if now >= state.expiry_unix_ts() {
            return Err(ShieldedPoolError::CacheExpired.into());
        }
        if state.frozen != 0 {
            return Err(ShieldedPoolError::CacheFrozen.into());
        }
        let commitment = state
            .commitments
            .get(usize::from(slot))
            .ok_or(ShieldedPoolError::InvalidCacheSlot)?;
        if *commitment != [0; 32] {
            return Err(ShieldedPoolError::CacheSlotOccupied.into());
        }
        Ok(Some(Self {
            state,
            address,
            slot,
        }))
    }

    pub fn destination(&self) -> (&[u8; 32], u8) {
        (&self.address, self.slot)
    }

    pub fn owner_identity(&self) -> [u8; 32] {
        self.state.owner_identity
    }

    pub fn write(mut self, output: &[u8; 32], output_tree_id: [u8; 32]) -> ProgramResult {
        if output_tree_id != tree_id_field(u16::from_le_bytes(self.state.tree_id)) {
            return Err(ShieldedPoolError::CacheTreeMismatch.into());
        }
        let entry = self
            .state
            .commitments
            .get_mut(usize::from(self.slot))
            .ok_or(ShieldedPoolError::InvalidCacheSlot)?;
        *entry = *output;
        Ok(())
    }
}
