use custom_ring_interface::KeyRegistryRoot;
use pinocchio::{AccountView, Address, ProgramResult};
use zolana_account_checks::AccountIterator;

use crate::{
    error::CustomRingError,
    instructions::{loader::load_authorized_config, shared::PdaCreate},
    state::KeyRegistryRootInit,
};

#[inline(never)]
pub fn process_create_key_registry_root_ix(
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
    let root_account = iter.next_mut("key_registry_root")?;
    let system_program = iter.next_account("system_program")?;

    // 1. Require the config authority before initializing shared compressed
    // state.
    if !pinocchio_system::check_id(system_program.address()) {
        return Err(CustomRingError::InvalidSystemProgram.into());
    }
    load_authorized_config(program_id, config_account, authority)?;

    // 2. Initialize the canonical root once, never reset an existing registry.
    let bump = PdaCreate {
        program_id,
        payer,
        seeds: &[KeyRegistryRoot::SEED],
        mismatch: CustomRingError::InvalidKeyRegistryRoot,
    }
    .create::<KeyRegistryRoot>(root_account)?;
    KeyRegistryRootInit { bump }.init(root_account)
}
