use pinocchio::{AccountView, ProgramResult};
use zolana_account_checks::AccountIterator;
use zolana_interface::error::ShieldedPoolError;

use crate::instructions::ring_config::loader::load_and_validate_ring_authority_mut;

pub fn process_update_ring_config_owner(
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    if !data.is_empty() {
        return Err(ShieldedPoolError::InvalidInstructionData.into());
    }
    let mut iter = AccountIterator::new(accounts);
    let authority = iter.next_signer("authority")?;
    let config = iter.next_mut("ring_config")?;
    let new_authority = iter.next_signer("new_authority")?;

    let mut current = load_and_validate_ring_authority_mut(config, authority)?;
    current.authority = new_authority.address().into();
    Ok(())
}
