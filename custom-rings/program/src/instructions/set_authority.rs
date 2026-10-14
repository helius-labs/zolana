use custom_ring_interface::{CustomRingError, RingProgramConfig};
use pinocchio::{AccountView, Address, ProgramResult};
use zolana_account_checks::AccountIterator;

use crate::instructions::loader::load_mut;

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
    let config = iter.next_mut("config")?;

    let mut config = load_mut::<RingProgramConfig>(program_id, config)?;
    if authority.address() != &config.authority {
        return Err(CustomRingError::UnauthorizedAuthority.into());
    }
    config.authority = *new_authority.address();
    Ok(())
}
