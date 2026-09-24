use super::loader::load_cache;
use pinocchio::{
    address::address_eq,
    error::ProgramError,
    sysvars::{clock::Clock, Sysvar},
    AccountView, ProgramResult,
};
use zolana_account_checks::AccountIterator;
use zolana_interface::error::ShieldedPoolError;

/// Accounts: cache (writable), rent recipient (writable), optional writer (signer).
/// The write authority may close a cache before expiry; after expiry
/// anyone may close. Rent always returns to the stored sponsor. Closing cancels
/// the fast path; normal tree spending and nullifier protection remain.
pub fn process_close_cache(accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    if !data.is_empty() {
        return Err(ShieldedPoolError::InvalidInstructionData.into());
    }
    let writer_present = accounts.len() == 3;
    let mut iter = AccountIterator::new(accounts);
    let cache = iter.next_mut("cache")?;
    let recipient = iter.next_mut("rent_recipient")?;
    let writer = iter.next_option_signer("cache_writer", writer_present)?;
    if !iter.remaining_unchecked_mut()?.is_empty() {
        return Err(ShieldedPoolError::InvalidInstructionData.into());
    }
    let clock = Clock::get()?;
    {
        let state = load_cache(cache)?;
        if clock.unix_timestamp < state.expiry_unix_ts() {
            let writer = writer.ok_or(ShieldedPoolError::CacheNotExpired)?;
            if !address_eq(writer.address(), &state.write_authority) {
                return Err(ShieldedPoolError::CacheWriteAuthorityMismatch.into());
            }
        }
        if !address_eq(recipient.address(), &state.rent_sponsor) {
            return Err(ShieldedPoolError::CacheRentRecipientMismatch.into());
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
