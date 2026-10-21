use custom_ring_interface::{
    CustomRingError, ReadAccessRecord, ReaderIxData, RingAccount, READ_ACCESS_RECORD,
};
use pinocchio::{AccountView, Address, ProgramResult};
use zolana_account_checks::AccountIterator;

use crate::{
    instructions::{
        loader::{load, load_authorized_config},
        shared::{check_system_program, close_into, parse, Pda},
    },
    state::{check_reader_key, Init},
};

#[inline(never)]
pub fn process_grant_read_access_ix(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    let ReaderIxData { reader } = parse(data)?;
    check_reader_key(&reader)?;

    let mut iter = AccountIterator::new(accounts);
    let payer = iter.next_signer_mut("payer")?;
    let authority = iter.next_signer("authority")?;
    let config = iter.next_account("config")?;
    let record = iter.next_mut("read_access_record")?;
    let system_program = iter.next_account("system_program")?;

    check_system_program(system_program)?;
    load_authorized_config(program_id, config, authority)?;
    let seed_hash = ReadAccessRecord::seed_hash(&reader).map_err(CustomRingError::from)?;
    let bump = Pda {
        program_id,
        seeds: &[ReadAccessRecord::SEED, &seed_hash],
    }
    .create::<ReadAccessRecord>(payer, record)?;
    Init(&ReadAccessRecord {
        discriminator: READ_ACCESS_RECORD,
        reader,
        bump,
    })
    .init(record)
}

#[inline(never)]
pub fn process_revoke_read_access_ix(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    let ReaderIxData { reader } = parse(data)?;
    let mut iter = AccountIterator::new(accounts);
    let authority = iter.next_signer("authority")?;
    let config = iter.next_account("config")?;
    let record = iter.next_mut("read_access_record")?;
    let rent_recipient = iter.next_mut("rent_recipient")?;

    load_authorized_config(program_id, config, authority)?;
    if load::<ReadAccessRecord>(program_id, record)?.reader != reader {
        return Err(ReadAccessRecord::INVALID.into());
    }
    close_into(record, rent_recipient, ReadAccessRecord::INVALID)
}
