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
    shared::reimburse_forester,
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
    let reimbursement_recipient = iter.next_mut("reimbursement_recipient")?;

    let config = load_protocol_config(protocol_config)?;
    config
        .check_forester_authority(authority.address())
        .map_err(ShieldedPoolError::from)?;
    drop(config);

    let event = {
        let mut tree_account =
            TreeAccount::from_account_view_mut(&mut *tree, &crate::ID, TREE_ACCOUNT_DISCRIMINATOR)
                .map_err(ShieldedPoolError::from)?;
        tree_account
            .nullifer_tree()
            .update_tree_from_address_queue(instruction)
            .map_err(|_| ShieldedPoolError::NullifierTreeUpdateFailed)?
    };

    if let Some(event) = event {
        reimburse_forester(tree, reimbursement_recipient, event.num_update)?;
        emit_batch_address_append_event(&event)?;
    }
    Ok(())
}

/// Batch incarnation: N proofs, one RLC, same accounts as legacy.
pub fn process_batch_update_nullifier_tree_many(
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    let updates = Vec::<BatchUpdateNullifierTreeData>::try_from_slice(data)
        .map_err(|_| ShieldedPoolError::InvalidInstructionData)?;
    if updates.is_empty() {
        return Err(ShieldedPoolError::InvalidInstructionData.into());
    }
    let mut iter = AccountIterator::new(accounts);
    let authority = iter.next_signer("authority")?;
    let protocol_config = iter.next_account("protocol_config")?;
    let tree = iter.next_mut("tree")?;
    let reimbursement_recipient = iter.next_mut("reimbursement_recipient")?;

    let config = load_protocol_config(protocol_config)?;
    config
        .check_forester_authority(authority.address())
        .map_err(ShieldedPoolError::from)?;
    drop(config);

    let event = {
        let mut tree_account =
            TreeAccount::from_account_view_mut(&mut *tree, &crate::ID, TREE_ACCOUNT_DISCRIMINATOR)
                .map_err(ShieldedPoolError::from)?;
        tree_account
            .nullifer_tree()
            .update_tree_from_address_queue_many(&updates)
            .map_err(|_| ShieldedPoolError::NullifierTreeUpdateFailed)?
    };

    if let Some(event) = event {
        reimburse_forester(tree, reimbursement_recipient, event.num_update)?;
        emit_batch_address_append_event(&event)?;
    }
    Ok(())
}
