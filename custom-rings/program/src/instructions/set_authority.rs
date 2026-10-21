use pinocchio::{AccountView, Address, ProgramResult};
use zolana_account_checks::AccountIterator;

use crate::instructions::{loader::load_authorized_config_mut, shared::no_data};

/// The new authority signs too, a mistyped address cannot strand the config.
#[inline(never)]
pub fn process_set_authority_ix(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    no_data(data)?;
    let mut iter = AccountIterator::new(accounts);
    let authority = iter.next_signer("authority")?;
    let new_authority = iter.next_signer("new_authority")?;
    let config = iter.next_mut("config")?;
    load_authorized_config_mut(program_id, config, authority)?.authority = *new_authority.address();
    Ok(())
}
