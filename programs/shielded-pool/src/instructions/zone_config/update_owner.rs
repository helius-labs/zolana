use borsh::BorshDeserialize;
use pinocchio::{AccountView, ProgramResult};
use zolana_account_checks::AccountIterator;
use zolana_interface::{error::ShieldedPoolError, instruction::UpdateZoneConfigOwnerData};

use crate::instructions::zone_config::loader::load_and_validate_zone_authority_mut;

pub fn process_update_zone_config_owner(
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    let data = UpdateZoneConfigOwnerData::try_from_slice(data)
        .map_err(|_| ShieldedPoolError::InvalidInstructionData)?;
    let mut iter = AccountIterator::new(accounts);
    let authority = iter.next_signer("authority")?;
    let config = iter.next_mut("zone_config")?;
    let new_authority = iter.next_signer("new_authority")?;

    if new_authority.address().to_bytes() != data.new_authority.to_bytes() {
        return Err(ShieldedPoolError::InvalidInstructionData.into());
    }

    let mut current = load_and_validate_zone_authority_mut(config, authority)?;
    current.authority = data.new_authority;
    Ok(())
}
