use bytemuck::from_bytes_mut;
use custom_ring_interface::RingProgramConfig;
use pinocchio::{AccountView, Address, ProgramResult};
use zolana_account_checks::AccountIterator;

use crate::{error::CustomRingError, instructions::loader::load_authorized_config};

/// The new authority signs too, a mistyped address cannot strand the config.
#[inline(never)]
pub fn process_set_authority_ix(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    if !data.is_empty() {
        return Err(CustomRingError::InvalidInstructionData.into());
    }

    let mut iter = AccountIterator::new(accounts);
    let authority = iter.next_signer("authority")?;
    let new_authority = iter.next_signer("new_authority")?;
    let config_account = iter.next_mut("config")?;

    load_authorized_config(program_id, config_account, authority)?;

    let new_authority = *new_authority.address();
    let mut config_data = config_account.try_borrow_mut()?;
    let config: &mut RingProgramConfig = from_bytes_mut(&mut config_data);
    config.authority = new_authority;
    Ok(())
}
