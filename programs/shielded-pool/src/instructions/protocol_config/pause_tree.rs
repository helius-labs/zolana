use light_account_checks::AccountIterator;
use pinocchio::{AccountView, ProgramResult};
use zolana_interface::{
    error::ShieldedPoolError, instruction::PauseTreeData,
    state::discriminator::TREE_ACCOUNT_DISCRIMINATOR,
};
use zolana_tree::TreeAccount;

use crate::instructions::protocol_config::loader::load_and_validate_protocol_authority;

pub fn process_pause_tree(accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    let data = *bytemuck::try_from_bytes::<PauseTreeData>(data)
        .map_err(|_| ShieldedPoolError::InvalidInstructionData)?;
    let mut iter = AccountIterator::new(accounts);
    let authority = iter.next_signer("authority")?;
    let protocol_config = iter.next_account("protocol_config")?;
    let tree = iter.next_mut("tree")?;

    load_and_validate_protocol_authority(protocol_config, authority)?;

    let mut tree_account = TreeAccount::from_account_view_mut_allow_paused(
        tree,
        &crate::ID,
        TREE_ACCOUNT_DISCRIMINATOR,
    )
    .map_err(ShieldedPoolError::from)?;
    tree_account.set_paused(data.paused != 0);
    Ok(())
}
