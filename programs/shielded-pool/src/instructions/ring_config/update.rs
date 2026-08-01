use borsh::BorshDeserialize;
use pinocchio::{AccountView, ProgramResult};
use zolana_account_checks::AccountIterator;
use zolana_interface::{error::ShieldedPoolError, instruction::UpdateRingConfigData};

use crate::instructions::ring_config::loader::load_and_validate_ring_authority_mut;

pub fn process_update_ring_config(accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    let data = UpdateRingConfigData::try_from_slice(data)
        .map_err(|_| ShieldedPoolError::InvalidInstructionData)?;
    let mut iter = AccountIterator::new(accounts);
    let authority = iter.next_signer("authority")?;
    let config = iter.next_mut("ring_config")?;

    let mut current = load_and_validate_ring_authority_mut(config, authority)?;
    current.ring_authority_transact_is_enabled = u8::from(data.ring_authority_transact_is_enabled);
    Ok(())
}
