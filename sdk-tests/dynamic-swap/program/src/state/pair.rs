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
    /// The maker's settle window in slots: `settle` requires the current slot
    /// to be at most `Escrow.created_at + expiry_slots`, `cancel` requires it
    /// to be past that. Set at `create_pair` and immutable, so the maker
    /// cannot shrink or stretch the window on open escrows. Nonzero.
    pub expiry_slots: u64,
    /// The worst-case owed per escrow (destination asset): every open escrow
    /// reserves exactly this much of `available_liquidity`, and the `escrow_open`
    /// circuit caps `order_amount * execution_price` to it. Set at
    /// `create_pair` and immutable: `cancel` must release exactly what
    /// `create_escrow` reserved. Nonzero.
    pub max_order_size: u64,
    /// Public lower bound on the pool's counted liquidity (destination asset).
    /// Invariant: `sum(booked over pool notes) >= available_liquidity +
    /// open_reservations * max_order_size`, maintained purely by public
    /// deltas -- deposits and rebalance credits raise it, withdrawals and
    /// escrow reservations lower it, settle leaves it untouched.
    pub available_liquidity: u64,
    /// Number of open escrows, each holding a `max_order_size` reservation
    /// carved out of `available_liquidity`. Settle and cancel each release one.
    pub open_reservations: u64,
    /// The source asset's UTXO commitment (`asset_field(source_mint)` =
    /// `hash_bytes(source_mint)`), supplied at `create_pair` time. The program
    /// has only the `source_asset_id` registry number, not a mint->field map,
    /// so this canonical commitment is client-supplied. `create_escrow` feeds
    /// it as the `escrow_open` circuit's `SourceAsset` public input, binding the
    /// escrowed source UTXO's asset to the pair (without it a caller could
    /// escrow a worthless token and drain the destination asset on settle).
    pub source_asset: [u8; 32],
    pub destination_asset: [u8; 32],
    /// The maker receipt destination: the shielded owner-hash `settle` pays the
    /// source asset to, supplied at `create_pair` time and fed as the
    /// `pool_settle` circuit's `ReceiptOwnerHash` public input. Immutable.
    pub maker_receipt_owner_hash: [u8; 32],
    /// The maker's encryption pubkey (SEC1-compressed P256), supplied at
    /// `create_pair` time -- the PDA-role viewing pubkey the maker derives from
    /// its own viewing key bound to the escrow_authority PDA. `create_escrow`
    /// encrypts the order UTXO data to it so the maker can settle without
    /// contacting the taker. Immutable: a rotation would orphan in-flight
    /// handoffs.
    pub maker_encryption_pubkey: [u8; 33],
    pub _pad2: [u8; 7],
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

const _: () = assert!(Pair::SIZE == 232);

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
