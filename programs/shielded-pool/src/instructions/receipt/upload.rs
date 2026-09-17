use pinocchio::{AccountView, ProgramResult};
use zolana_account_checks::AccountIterator;
use zolana_interface::{
    error::ShieldedPoolError, instruction::UploadReceiptData,
    state::receipt::receipt_nullifiers_mut,
};

use super::loader::{header, header_mut, load_receipt_mut};
use crate::instructions::shared::check_field_elements;

/// Accounts: sponsor (signer), receipt (writable). Appends `nullifiers` at
/// `offset`, which must be the next unfilled slot; rejected once verified.
/// Zero is not a nullifier and marks padding, so it cannot be uploaded.
pub fn process_upload_receipt(accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    let ix = UploadReceiptData::from_bytes(data)
        .map_err(|_| ShieldedPoolError::InvalidInstructionData)?;
    let mut iter = AccountIterator::new(accounts);
    let sponsor = iter.next_signer("rent_sponsor")?;
    let receipt = iter.next_mut("receipt")?;
    if !iter.remaining_unchecked_mut()?.is_empty() {
        return Err(ShieldedPoolError::InvalidInstructionData.into());
    }
    check_field_elements(
        ix.nullifiers.iter(),
        "receipt nullifier",
        ShieldedPoolError::NonCanonicalReceiptNullifier,
    )?;
    if ix.nullifiers.contains(&[0; 32]) {
        return Err(ShieldedPoolError::NonCanonicalReceiptNullifier.into());
    }
    let mut bytes = load_receipt_mut(receipt)?;
    let (capacity, filled) = {
        let current = header(&bytes);
        if current.rent_sponsor != sponsor.address().to_bytes() {
            return Err(ShieldedPoolError::InvalidReceiptSponsor.into());
        }
        if current.verified != 0 {
            return Err(ShieldedPoolError::ReceiptAlreadyVerified.into());
        }
        (
            usize::from(current.capacity()),
            usize::from(current.filled()),
        )
    };
    let offset = usize::from(ix.offset);
    let end = offset
        .checked_add(ix.nullifiers.len())
        .ok_or(ShieldedPoolError::ReceiptUploadOutOfOrder)?;
    if offset != filled || end > capacity {
        return Err(ShieldedPoolError::ReceiptUploadOutOfOrder.into());
    }
    receipt_nullifiers_mut(&mut bytes)[offset..end].copy_from_slice(&ix.nullifiers);
    header_mut(&mut bytes).filled = (end as u16).to_le_bytes();
    Ok(())
}
