use pinocchio::{error::ProgramError, AccountView, ProgramResult};
use zolana_account_checks::AccountIterator;
use zolana_interface::error::ShieldedPoolError;

use super::loader::{header, load_receipt};

/// Accounts: sponsor (signer, writable, receives the rent), receipt
/// (writable). Closing a receipt only removes the fast path for merges that
/// have not landed yet; settled merges are unaffected.
pub fn process_close_receipt(accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    if !data.is_empty() {
        return Err(ShieldedPoolError::InvalidInstructionData.into());
    }
    let mut iter = AccountIterator::new(accounts);
    let sponsor = iter.next_signer_mut("rent_sponsor")?;
    let receipt = iter.next_mut("receipt")?;
    if !iter.remaining_unchecked_mut()?.is_empty() {
        return Err(ShieldedPoolError::InvalidInstructionData.into());
    }
    {
        let bytes = load_receipt(receipt)?;
        if header(&bytes).rent_sponsor != sponsor.address().to_bytes()
            || sponsor.address() == receipt.address()
        {
            return Err(ShieldedPoolError::InvalidReceiptSponsor.into());
        }
    }
    let balance = sponsor
        .lamports()
        .checked_add(receipt.lamports())
        .ok_or(ProgramError::ArithmeticOverflow)?;
    sponsor.set_lamports(balance);
    receipt.set_lamports(0);
    receipt.close()
}
