use borsh::BorshDeserialize;
use pinocchio::{AccountView, ProgramResult};
use zolana_account_checks::AccountIterator;
use zolana_interface::{
    error::ShieldedPoolError, instruction::BatchUpdateNullifierTreeData,
    state::discriminator::TREE_ACCOUNT_DISCRIMINATOR,
};
use zolana_tree::TreeAccount;

use crate::instructions::{
    event::emit_batch_address_append_event, protocol_config::loader::load_protocol_config,
};

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

    let event = tree
        .nullifer_tree()
        .update_tree_from_address_queue(instruction)
        .map_err(|_| ShieldedPoolError::NullifierTreeUpdateFailed)?;

    // The emit self-CPI passes no accounts, so the tree borrow does not conflict.
    if let Some(event) = event {
        emit_batch_address_append_event(&event)?;
    }
    Ok(())
}
