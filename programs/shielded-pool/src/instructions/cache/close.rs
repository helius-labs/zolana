use super::loader::load_cache;
use pinocchio::{error::ProgramError, AccountView, ProgramResult};
use zolana_account_checks::AccountIterator;
use zolana_interface::error::ShieldedPoolError;

/// Accounts: cache (writable), close authority (signer), rent recipient (writable).
/// Closing cancels the fast path; normal tree spending and nullifier protection remain.
pub fn process_close_cache(accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    if !data.is_empty() {
        return Err(ShieldedPoolError::InvalidInstructionData.into());
    }
    let mut iter = AccountIterator::new(accounts);
    let cache = iter.next_mut("cache")?;
    let authority = iter.next_signer("close_authority")?;
    let recipient = iter.next_mut("rent_recipient")?;
    {
        let state = load_cache(cache)?;
        if authority.address().as_array() != &state.close_authority {
            return Err(ShieldedPoolError::UnauthorizedCaller.into());
        }
        if recipient.address().as_array() != &state.rent_sponsor
            || recipient.address() == cache.address()
        {
            return Err(ShieldedPoolError::InvalidReimbursementRecipient.into());
        }
    }
    let balance = recipient
        .lamports()
        .checked_add(cache.lamports())
        .ok_or(ProgramError::ArithmeticOverflow)?;
    recipient.set_lamports(balance);
    cache.set_lamports(0);
    cache.close()
}
