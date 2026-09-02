use pinocchio::{AccountView, ProgramResult};
use zolana_account_checks::AccountIterator;
use zolana_interface::{
    error::ShieldedPoolError, state::discriminator::TREE_ACCOUNT_DISCRIMINATOR,
};
use zolana_tree::TreeAccount;

use crate::instructions::{
    nullifier_pda::NullifierPdaClose,
    protocol_config::loader::validate_forester_authority,
    shared::{check_reimbursement_recipient, pay_reimbursement, tree_error},
};

#[inline(never)]
pub fn process_close_nullifier_pdas(accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    if !data.is_empty() {
        return Err(ShieldedPoolError::InvalidInstructionData.into());
    }
    let mut iter = AccountIterator::new(accounts);
    let authority = iter.next_signer("authority")?;
    let protocol_config = iter.next_account("protocol_config")?;
    let tree = iter.next_mut("tree")?;
    let reimbursement_recipient = iter.next_mut("reimbursement_recipient")?;
    validate_forester_authority(protocol_config, authority)?;
    check_reimbursement_recipient(reimbursement_recipient)?;
    if iter.iterator_is_empty() {
        return Err(ShieldedPoolError::InvalidInstructionData.into());
    }
    let closed = (iter.len() - iter.position()) as u64;
    let (close, paid) = {
        let mut tree_account =
            TreeAccount::from_account_view_mut(&mut *tree, &crate::ID, TREE_ACCOUNT_DISCRIMINATOR)
                .map_err(tree_error)?;
        let close = NullifierPdaClose {
            tree_id: tree_account.tree_id(),
            close_before_index: tree_account.close_before_index(),
        };
        let paid = tree_account.take_close_reimbursement(closed);
        (close, paid)
    };
    while !iter.iterator_is_empty() {
        let nullifier_pda = iter.next_mut("nullifier_pda")?;
        close.close(tree, nullifier_pda)?;
    }
    pay_reimbursement(tree, reimbursement_recipient, paid)
}
