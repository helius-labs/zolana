use custom_ring_interface::{ReaderIxData, ReaderKeyBytes, ReaderRecord};
use pinocchio::{
    cpi::{Seed, Signer},
    AccountView, ProgramResult,
};
use zolana_account_checks::AccountIterator;

use crate::{
    error::CustomRingError,
    instructions::{loader::load_authorized_config, shared::PdaCheck},
    state::{check_reader_key, ReaderRecordInitParams},
};

#[inline(never)]
pub fn process_grant_reader_ix(accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    let reader = parse_reader(data)?;
    check_reader_key(&reader)?;

    let mut iter = AccountIterator::new(accounts);
    let payer = iter.next_signer_mut("payer")?;
    let authority = iter.next_signer("authority")?;
    let config_account = iter.next_account("config")?;
    let record_account = iter.next_mut("reader_record")?;
    let system_program = iter.next_account("system_program")?;

    if !pinocchio_system::check_id(system_program.address()) {
        return Err(CustomRingError::InvalidSystemProgram.into());
    }
    load_authorized_config(config_account, authority)?;

    let seed_hash = ReaderRecord::seed_hash(&reader).map_err(|_| CustomRingError::HashingFailed)?;
    let bump = PdaCheck {
        address: record_account.address(),
        seeds: &[ReaderRecord::SEED, &seed_hash],
        mismatch: CustomRingError::InvalidReaderRecord,
    }
    .verify()?;
    if record_account.data_len() != 0 {
        return Err(CustomRingError::ReaderRecordAlreadyExists.into());
    }

    let bump_seed = [bump];
    let seeds = [
        Seed::from(ReaderRecord::SEED),
        Seed::from(seed_hash.as_ref()),
        Seed::from(bump_seed.as_ref()),
    ];
    pinocchio_system::create_account_with_minimum_balance_signed(
        record_account,
        ReaderRecord::SIZE,
        &crate::ID,
        payer,
        None,
        &[Signer::from(seeds.as_ref())],
    )?;

    ReaderRecordInitParams { reader, bump }.init(record_account)
}

pub(crate) fn parse_reader(data: &[u8]) -> Result<ReaderKeyBytes, CustomRingError> {
    let ReaderIxData { reader } =
        wincode::deserialize_exact(data).map_err(|_| CustomRingError::InvalidInstructionData)?;
    Ok(reader)
}
