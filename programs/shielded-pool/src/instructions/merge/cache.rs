use crate::instructions::cache::loader::load_cache_mut;
use pinocchio::{account::RefMut, error::ProgramError, AccountView, ProgramResult};
use zolana_interface::{
    error::ShieldedPoolError,
    state::{
        cache::{CACHE_OWNER_REGISTRY, CACHE_OWNER_RING},
        CacheAccount,
    },
    tree_slot::tree_id_field,
};

pub(crate) enum CacheAuthority {
    Registry([u8; 32]),
    /// The signing ring authorizes the destination, including access within its ring.
    Ring([u8; 32]),
}

pub(crate) struct CacheSlot<'a> {
    state: RefMut<'a, CacheAccount>,
    address: [u8; 32],
    slot: u8,
}

impl<'a> CacheSlot<'a> {
    pub fn open(
        account: &'a mut AccountView,
        slot: u8,
        authority: CacheAuthority,
    ) -> Result<Self, ProgramError> {
        let address = account.address().to_bytes();
        let state = load_cache_mut(account)?;
        let (kind, owner) = match authority {
            CacheAuthority::Registry(owner) => (CACHE_OWNER_REGISTRY, owner),
            CacheAuthority::Ring(program_id) => (CACHE_OWNER_RING, program_id),
        };
        if state.owner_kind != kind || state.owner != owner {
            return Err(ShieldedPoolError::CacheOwnerMismatch.into());
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
        Ok(Self {
            state,
            address,
            slot,
        })
    }

    pub fn destination(&self) -> (&[u8; 32], u8) {
        (&self.address, self.slot)
    }

    pub fn write(mut self, output: &[u8; 32], output_tree_id: [u8; 32]) -> ProgramResult {
        if output_tree_id != tree_id_field(u16::from_le_bytes(self.state.tree_id)) {
            return Err(ShieldedPoolError::CacheTreeMismatch.into());
        }
        if *output == [0; 32] {
            return Err(ShieldedPoolError::CacheSlotEmpty.into());
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
