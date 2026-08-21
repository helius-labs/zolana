use pinocchio::{error::ProgramError, AccountView, ProgramResult};
use zolana_account_checks::AccountIterator;

use crate::{
    error::CustomRingError,
    instructions::{
        grant_reader::parse_reader,
        loader::{load_authorized_config, load_reader_record},
    },
};

#[inline(never)]
pub fn process_revoke_reader_ix(accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    let reader = parse_reader(data)?;

    let mut iter = AccountIterator::new(accounts);
    let authority = iter.next_signer("authority")?;
    let config_account = iter.next_account("config")?;
    let record_account = iter.next_mut("reader_record")?;
    let rent_recipient = iter.next_mut("rent_recipient")?;
    if record_account.address() == rent_recipient.address() {
        return Err(CustomRingError::InvalidReaderRecord.into());
    }

    load_authorized_config(config_account, authority)?;
    load_reader_record(record_account, &reader)?;

    let refund = rent_recipient
        .lamports()
        .checked_add(record_account.lamports())
        .ok_or(ProgramError::ArithmeticOverflow)?;
    rent_recipient.set_lamports(refund);
    record_account.set_lamports(0);
    record_account.close()
}
