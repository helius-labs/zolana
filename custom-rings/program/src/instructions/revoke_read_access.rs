use pinocchio::{AccountView, Address, ProgramResult};
use zolana_account_checks::AccountIterator;

use crate::{
    error::CustomRingError,
    instructions::{
        grant_read_access::parse_reader,
        loader::{load_authorized_config, load_read_access_record},
        shared::close_into,
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
    let record_account = iter.next_mut("read_access_record")?;
    let rent_recipient = iter.next_mut("rent_recipient")?;

    load_authorized_config(program_id, config_account, authority)?;
    load_read_access_record(program_id, record_account, &reader)?;
    close_into(
        record_account,
        rent_recipient,
        CustomRingError::InvalidReadAccessRecord,
    )
}
