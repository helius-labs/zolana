use borsh::BorshDeserialize;
use light_account_checks::AccountIterator;
use pinocchio::{AccountView, ProgramResult};
use zolana_interface::{
    error::ShieldedPoolError, instruction::BatchUpdateNullifierTreeData,
    state::discriminator::TREE_ACCOUNT_DISCRIMINATOR,
};
use zolana_tree::TreeAccount;

use crate::instructions::protocol_config::loader::load_protocol_config;

pub fn process_batch_update_nullifier_tree(
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    let instruction = BatchUpdateNullifierTreeData::try_from_slice(data)
        .map_err(|_| ShieldedPoolError::InvalidInstructionData)?;
    let mut iter = AccountIterator::new(accounts);
    let authority = iter.next_signer("authority")?;
    let protocol_config = iter.next_account("protocol_config")?;
    let tree = iter.next_mut("tree")?;

    let config = load_protocol_config(protocol_config)?;
    config
        .check_forester_authority(authority.address())
        .map_err(ShieldedPoolError::from)?;
    drop(config);

    let mut tree = TreeAccount::from_account_view_mut(tree, &crate::ID, TREE_ACCOUNT_DISCRIMINATOR)
        .map_err(ShieldedPoolError::from)?;

    if tree
        .nullifer_tree()
        .update_tree_from_address_queue(instruction)
        .is_err()
    {
        return Err(ShieldedPoolError::NullifierTreeUpdateFailed.into());
    }
    Ok(())
}
