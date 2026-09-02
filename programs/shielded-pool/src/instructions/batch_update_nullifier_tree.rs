use borsh::BorshDeserialize;
use pinocchio::{AccountView, ProgramResult};
use zolana_account_checks::AccountIterator;
use zolana_interface::{
    error::ShieldedPoolError, instruction::BatchUpdateNullifierTreeData,
    state::discriminator::TREE_ACCOUNT_DISCRIMINATOR,
};
use zolana_tree::TreeAccount;

use crate::instructions::{
    event::emit_batch_nullifier_append_event,
    protocol_config::loader::validate_forester_authority,
    shared::{check_reimbursement_recipient, nullifier_tree_error, pay_reimbursement},
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

    validate_forester_authority(protocol_config, authority)?;
    check_reimbursement_recipient(reimbursement_recipient)?;

    let applied = {
        let mut tree_account =
            TreeAccount::from_account_view_mut(&mut *tree, &crate::ID, TREE_ACCOUNT_DISCRIMINATOR)
                .map_err(ShieldedPoolError::from)?;
        let tree_pubkey = tree_account.pubkey();
        let event = tree_account
            .nullifier_tree()
            .update_tree_from_queue(tree_pubkey, instruction)
            .map_err(nullifier_tree_error)?;
        match event {
            Some(event) => {
                let paid = tree_account.take_append_reimbursement(event.num_update);
                Some((event, paid))
            }
            None => None,
        }
    };

    // The emit self-CPI passes no accounts, so the tree borrow does not conflict.
    // INVARIANT: the event emit must remain the LAST fallible operation in this
    // processor. Photon's parser records batch updates from the emitted event in
    // successful transactions only (its `tx.error` guard); an emit-then-fail
    // shape would either drop a genuine update or wedge the indexer on a forged
    // one. Keep every fallible step (including `pay_reimbursement`) above it.
    if let Some((event, paid)) = applied {
        pay_reimbursement(tree, reimbursement_recipient, paid)?;
        emit_batch_nullifier_append_event(&event)?;
    }
    Ok(())
}
