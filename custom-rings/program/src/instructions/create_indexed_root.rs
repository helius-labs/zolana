use pinocchio::{AccountView, Address, ProgramResult};
use zolana_account_checks::AccountIterator;

use crate::{
    error::CustomRingError,
    instructions::{loader::load_authorized_config, shared::PdaCreate},
    state::{AppendRoot, SentinelRootInit},
};

#[inline(never)]
pub fn process_create_indexed_root_ix<T: AppendRoot>(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    if !data.is_empty() {
        return Err(CustomRingError::InvalidInstructionData.into());
    }
    let mut iter = AccountIterator::new(accounts);
    let payer = iter.next_signer_mut("payer")?;
    let authority = iter.next_signer("authority")?;
    let config_account = iter.next_account("config")?;
    let root_account = iter.next_mut("indexed_root")?;
    let system_program = iter.next_account("system_program")?;

    if !pinocchio_system::check_id(system_program.address()) {
        return Err(CustomRingError::InvalidSystemProgram.into());
    }
    load_authorized_config(program_id, config_account, authority)?;

    let bump = PdaCreate {
        program_id,
        payer,
        seeds: &[T::SEED],
        mismatch: T::NOT_INITIALIZED,
    }
    .create::<T>(root_account)?;
    SentinelRootInit { bump }.init::<T>(root_account)
}
