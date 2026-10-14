use custom_ring_interface::{CustomRingError, ReadAccessRecord, ReaderIxData, READ_ACCESS_RECORD};
use pinocchio::{AccountView, Address, ProgramResult};
use zolana_account_checks::AccountIterator;

use crate::{
    instructions::{
        loader::load_authorized_config,
        shared::{check_system_program, create_pda, parse},
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
    let bump = create_pda::<ReadAccessRecord, 2>(
        program_id,
        payer,
        record,
        &[ReadAccessRecord::SEED, &seed_hash],
    )?;
    Init(&ReadAccessRecord {
        discriminator: READ_ACCESS_RECORD,
        reader,
        bump,
    })
    .init(record)
}
