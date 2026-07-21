use bytemuck::{from_bytes, from_bytes_mut, Pod, Zeroable};
use pinocchio::{
    account::{Ref, RefMut},
    error::ProgramError,
    AccountView, Address,
};

use super::discriminator::PAIR;
use crate::error::DynamicSwapError;

/// A unidirectional trading pair with an authority-set `price`.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Pod, Zeroable)]
#[repr(C)]
pub struct Pair {
    pub discriminator: u8,
    pub bump: u8,
    pub _pad: [u8; 6],
    pub authority: Address,
    pub source_asset_id: u64,
    pub destination_asset_id: u64,
    pub price: u64,
    /// The authority's own owner-hash commitment (`Poseidon(owner_pk_field,
    /// nullifier_pubkey)`), supplied at `create_pair` time. `settle`'s settle
    /// branch binds the settled source-asset leg's UTXO owner to this value,
    /// so the authority controls its own destination without resupplying it
    /// on every call.
    pub authority_owner_hash: [u8; 32],
    /// The source asset's UTXO commitment (`asset_field(source_mint)` =
    /// `hash_field(source_mint)`), supplied at `create_pair` time. The program
    /// has only the `source_asset_id` registry number, not a mint->field map,
    /// so this canonical commitment is client-supplied. `create_escrow` feeds
    /// it as the `escrow_open` circuit's `SourceAsset` public input, binding the
    /// escrowed source UTXO's asset to the pair (without it a caller could
    /// escrow a worthless token and drain the destination asset on settle).
    pub source_asset: [u8; 32],
    pub destination_asset: [u8; 32],
}

impl Pair {
    pub const SIZE: usize = core::mem::size_of::<Self>();
    pub const SEED_PREFIX: &'static [u8] = b"pair";

    pub fn check_discriminator(&self) -> Result<(), ProgramError> {
        (self.discriminator == PAIR)
            .then_some(())
            .ok_or_else(|| DynamicSwapError::InvalidInstructionData.into())
    }
}

const _: () = assert!(Pair::SIZE == 160);

#[inline(always)]
pub fn load_pair(account: &AccountView) -> Result<Ref<'_, Pair>, ProgramError> {
    if !account.owned_by(&crate::ID) {
        return Err(DynamicSwapError::InvalidInstructionData.into());
    }
    let data = account
        .try_borrow()
        .map_err(|_| DynamicSwapError::InvalidInstructionData)?;
    if data.len() != Pair::SIZE {
        return Err(DynamicSwapError::InvalidInstructionData.into());
    }
    let pair = Ref::map(data, |d| from_bytes::<Pair>(d));
    pair.check_discriminator()?;
    Ok(pair)
}

#[inline(always)]
pub fn load_pair_mut(account: &mut AccountView) -> Result<RefMut<'_, Pair>, ProgramError> {
    if !account.is_writable() || !account.owned_by(&crate::ID) {
        return Err(DynamicSwapError::InvalidInstructionData.into());
    }
    let data = account
        .try_borrow_mut()
        .map_err(|_| DynamicSwapError::InvalidInstructionData)?;
    if data.len() != Pair::SIZE {
        return Err(DynamicSwapError::InvalidInstructionData.into());
    }
    let pair = RefMut::map(data, |d| from_bytes_mut::<Pair>(d));
    pair.check_discriminator()?;
    Ok(pair)
}
