use light_account_checks::AccountIterator;
use pinocchio::{AccountView, ProgramResult};
use zolana_interface::instruction::UpdateZoneConfigOwnerData;

use crate::instructions::zone_config::loader::load_and_validate_zone_authority_mut;

pub fn process_update_zone_config_owner(
    accounts: &mut [AccountView],
    data: UpdateZoneConfigOwnerData,
) -> ProgramResult {
    let mut iter = AccountIterator::new(accounts);
    let authority = iter.next_signer("authority")?;
    let config = iter.next_mut("zone_config")?;

    let mut current = load_and_validate_zone_authority_mut(config, authority)?;
    current.authority = data.new_authority;
    Ok(())
}
