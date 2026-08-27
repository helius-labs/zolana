use pinocchio::{error::ProgramError, AccountView, Address, ProgramResult};
use zolana_account_checks::AccountIterator;

use crate::{
    error::CustomRingError,
    instructions::{
        grant_read_access::parse_reader,
        loader::{load_authorized_config, load_read_access_record},
    },
};

#[inline(never)]
pub fn process_revoke_read_access_ix(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    let reader = parse_reader(data)?;

    let mut iter = AccountIterator::new(accounts);
    let authority = iter.next_signer("authority")?;
    let config_account = iter.next_account("config")?;
    let entry_account = iter.next_mut("read_access_record")?;
    let rent_recipient = iter.next_mut("rent_recipient")?;
    if entry_account.address() == rent_recipient.address() {
        return Err(CustomRingError::InvalidReadAccessRecord.into());
    }

    load_authorized_config(program_id, config_account, authority)?;
    load_read_access_record(program_id, entry_account, &reader)?;

    let refund = rent_recipient
        .lamports()
        .checked_add(entry_account.lamports())
        .ok_or(ProgramError::ArithmeticOverflow)?;
    rent_recipient.set_lamports(refund);
    entry_account.set_lamports(0);
    entry_account.close()
}
