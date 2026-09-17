use pinocchio::{
    account::{Ref, RefMut},
    error::ProgramError,
    AccountView,
};
use zolana_interface::{
    error::ShieldedPoolError,
    state::receipt::{receipt_account_size, receipt_nullifiers, ReceiptHeader},
};

use crate::instructions::shared::caused_by;

fn validate(data: &[u8]) -> Result<&ReceiptHeader, ProgramError> {
    let header: &ReceiptHeader = bytemuck::try_from_bytes(
        data.get(..ReceiptHeader::SIZE)
            .ok_or(ShieldedPoolError::InvalidReceipt)?,
    )
    .map_err(caused_by(ShieldedPoolError::InvalidReceipt))?;
    if !header.has_discriminator() || data.len() != receipt_account_size(header.capacity()) {
        return Err(ShieldedPoolError::InvalidReceipt.into());
    }
    Ok(header)
}

/// Borrow a receipt account read-only: program-owned, discriminated, and
/// exactly header plus `capacity` slots long.
pub(crate) fn load_receipt(account: &AccountView) -> Result<Ref<'_, [u8]>, ProgramError> {
    if !account.owned_by(&crate::ID) {
        return Err(ShieldedPoolError::InvalidReceipt.into());
    }
    let data = account
        .try_borrow()
        .map_err(caused_by(ShieldedPoolError::InvalidReceipt))?;
    validate(&data)?;
    Ok(data)
}

pub(crate) fn load_receipt_mut(
    account: &mut AccountView,
) -> Result<RefMut<'_, [u8]>, ProgramError> {
    if !account.is_writable() || !account.owned_by(&crate::ID) {
        return Err(ShieldedPoolError::InvalidReceipt.into());
    }
    let data = account
        .try_borrow_mut()
        .map_err(caused_by(ShieldedPoolError::InvalidReceipt))?;
    validate(&data)?;
    Ok(data)
}

pub(crate) fn header(data: &[u8]) -> &ReceiptHeader {
    bytemuck::from_bytes(&data[..ReceiptHeader::SIZE])
}

pub(crate) fn header_mut(data: &mut [u8]) -> &mut ReceiptHeader {
    bytemuck::from_bytes_mut(&mut data[..ReceiptHeader::SIZE])
}

/// A verified receipt slice a merge spends: `nullifiers` are the receipt's
/// slots `[offset, offset + n)`, all within the live count.
pub(crate) struct ReceiptSlice<'a> {
    data: Ref<'a, [u8]>,
    offset: usize,
    len: usize,
}

impl<'a> ReceiptSlice<'a> {
    /// Load a verified receipt for `tree` and select `len` slots at `offset`.
    pub fn load(
        account: &'a AccountView,
        tree: &[u8; 32],
        offset: u16,
        len: usize,
    ) -> Result<Self, ProgramError> {
        let data = load_receipt(account)?;
        let header = header(&data);
        if header.verified == 0 {
            return Err(ShieldedPoolError::ReceiptNotVerified.into());
        }
        if header.tree != *tree {
            return Err(ShieldedPoolError::ReceiptTreeMismatch.into());
        }
        let offset = usize::from(offset);
        let end = offset
            .checked_add(len)
            .ok_or(ShieldedPoolError::ReceiptSliceMismatch)?;
        if end > usize::from(header.count()) {
            return Err(ShieldedPoolError::ReceiptSliceMismatch.into());
        }
        Ok(Self { data, offset, len })
    }

    pub fn nullifier_root(&self) -> [u8; 32] {
        header(&self.data).nullifier_root
    }

    pub fn nullifiers(&self) -> &[[u8; 32]] {
        &receipt_nullifiers(&self.data)[self.offset..self.offset + self.len]
    }
}
