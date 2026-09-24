use crate::instructions::cache::write::CacheWrite;
use pinocchio::{error::ProgramError, AccountView};
use zolana_account_checks::AccountIterator;
use zolana_interface::error::ShieldedPoolError;

/// The writable cache a merge names, the signer that must hold its write
/// authority, and the destination slot.
pub struct MergeCacheAccounts<'info> {
    pub cache: &'info mut AccountView,
    pub writer: &'info AccountView,
    pub slot: u8,
}

/// The trailing accounts both merge rails share. Neither rail accepts any
/// account beyond them.
pub(crate) fn parse_cache_accounts<'info>(
    mut iter: AccountIterator<'info>,
    cache_slot: Option<u8>,
) -> Result<Option<MergeCacheAccounts<'info>>, ProgramError> {
    let accounts = match cache_slot {
        Some(slot) => Some(MergeCacheAccounts {
            cache: iter.next_mut("cache")?,
            writer: iter.next_signer("cache_writer")?,
            slot,
        }),
        None => None,
    };
    if !iter.remaining_unchecked_mut()?.is_empty() {
        return Err(ShieldedPoolError::InvalidMergeShape.into());
    }
    Ok(accounts)
}

/// Load the cache a merge writes, if it names one: the writer, the expiry and
/// the destination slot, all before the proof.
pub(crate) fn load_merge_cache(
    accounts: Option<MergeCacheAccounts<'_>>,
    now: i64,
) -> Result<Option<(CacheWrite<'_>, u8)>, ProgramError> {
    let Some(MergeCacheAccounts {
        cache,
        writer,
        slot,
    }) = accounts
    else {
        return Ok(None);
    };
    let cache = CacheWrite::load(cache, writer, now)?;
    cache.check_slot(slot)?;
    Ok(Some((cache, slot)))
}
