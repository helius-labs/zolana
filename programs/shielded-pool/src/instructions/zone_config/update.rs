use borsh::BorshDeserialize;
use light_account_checks::AccountIterator;
use pinocchio::{AccountView, ProgramResult};
use zolana_interface::error::ShieldedPoolError;
use zolana_interface::instruction::UpdateZoneConfigData;

use crate::instructions::zone_config::loader::load_and_validate_zone_authority_mut;

pub fn process_update_zone_config(accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    let data = UpdateZoneConfigData::try_from_slice(data)
        .map_err(|_| ShieldedPoolError::InvalidInstructionData)?;
    let mut iter = AccountIterator::new(accounts);
    let authority = iter.next_signer("authority")?;
    let config = iter.next_mut("zone_config")?;

    let mut current = load_and_validate_zone_authority_mut(config, authority)?;
    current.zone_authority_transact_is_enabled = u8::from(data.zone_authority_transact_is_enabled);
    Ok(())
}
