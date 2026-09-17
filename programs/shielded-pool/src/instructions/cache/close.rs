use super::loader::load_cache;
use pinocchio::{
    error::ProgramError,
    sysvars::{clock::Clock, Sysvar},
    AccountView, ProgramResult,
};
use zolana_account_checks::AccountIterator;
use zolana_hasher::primitives::solana_owner_identity;
use zolana_interface::error::ShieldedPoolError;

/// Accounts: cache (writable), rent recipient (writable), optional owner (signer).
/// The default-ring owner may close a frozen cache before expiry; after expiry
/// anyone may close. Rent always returns to the stored sponsor. Closing cancels
/// the fast path; normal tree spending and nullifier protection remain.
pub fn process_close_cache(accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    if !data.is_empty() {
        return Err(ShieldedPoolError::InvalidInstructionData.into());
    }
    let owner_present = accounts.len() == 3;
    let mut iter = AccountIterator::new(accounts);
    let cache = iter.next_mut("cache")?;
    let recipient = iter.next_mut("rent_recipient")?;
    let owner = iter.next_option_signer("owner", owner_present)?;
    if !iter.remaining_unchecked_mut()?.is_empty() {
        return Err(ShieldedPoolError::InvalidInstructionData.into());
    }
    let clock = Clock::get()?;
    {
        let state = load_cache(cache)?;
        if clock.unix_timestamp < state.expiry_unix_ts() {
            if state.frozen == 0 {
                return Err(ShieldedPoolError::CacheNotExpired.into());
            }
            let owner = owner.ok_or(ShieldedPoolError::CacheNotExpired)?;
            if solana_owner_identity(owner.address().as_array())? != state.owner_identity {
                return Err(ShieldedPoolError::CacheOwnerMismatch.into());
            }
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
