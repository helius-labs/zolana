use custom_ring_interface::{
    CoSigner, CustomRingError, ReadAccessRecord, ReaderIxData, RingAccount, SpendWindow,
};
use pinocchio::{AccountView, Address, ProgramResult};
use zolana_account_checks::AccountIterator;

use crate::instructions::{
    loader::{load, load_authorized_config},
    shared::{close_into, parse},
};

#[inline(never)]
pub fn process_clear_cosigner_ix(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    if !data.is_empty() {
        return Err(CustomRingError::InvalidInstructionData.into());
    }
    close::<CoSigner>(program_id, accounts, |_| true)
}

#[inline(never)]
pub fn process_clear_spend_window_ix(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    let mint: [u8; 32] = data
        .try_into()
        .map_err(|_| CustomRingError::InvalidInstructionData)?;
    close::<SpendWindow>(program_id, accounts, |window| {
        window.mint.to_bytes() == mint
    })
}

#[inline(never)]
pub fn process_revoke_read_access_ix(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    let ReaderIxData { reader } = parse(data)?;
    close::<ReadAccessRecord>(program_id, accounts, |record| record.reader == reader)
}

/// `[authority(s), config, account(w), rent_recipient(w)]`, the config
/// authority closes `T` when `matches` holds.
fn close<T: RingAccount>(
    program_id: &Address,
    accounts: &mut [AccountView],
    matches: impl FnOnce(&T) -> bool,
) -> ProgramResult {
    let mut iter = AccountIterator::new(accounts);
    let authority = iter.next_signer("authority")?;
    let config = iter.next_account("config")?;
    let account = iter.next_mut("account")?;
    let rent_recipient = iter.next_mut("rent_recipient")?;

    load_authorized_config(program_id, config, authority)?;
    if !matches(&*load::<T>(program_id, account)?) {
        return Err(T::INVALID.into());
    }
    close_into(account, rent_recipient, T::INVALID)
}
