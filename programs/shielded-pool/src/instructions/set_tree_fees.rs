use crate::instructions::shared::caused_by;
use borsh::BorshDeserialize;
use pinocchio::{AccountView, ProgramResult};
use zolana_account_checks::AccountIterator;
use zolana_interface::{
    error::ShieldedPoolError, instruction::SetTreeFeesData,
    state::discriminator::TREE_ACCOUNT_DISCRIMINATOR,
};
use zolana_tree::TreeAccount;

use crate::instructions::{
    protocol_config::loader::load_and_validate_fee_authority, shared::tree_error,
};

pub fn process_set_tree_fees(accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    let fees = SetTreeFeesData::try_from_slice(data)
        .map_err(caused_by(ShieldedPoolError::InvalidInstructionData))?;
    let mut iter = AccountIterator::new(accounts);
    let authority = iter.next_signer("authority")?;
    let protocol_config = iter.next_account("protocol_config")?;
    let tree = iter.next_mut("tree")?;

    load_and_validate_fee_authority(protocol_config, authority)?;

    let mut tree_account = TreeAccount::from_account_view_mut_allow_paused(
        tree,
        &crate::ID,
        TREE_ACCOUNT_DISCRIMINATOR,
    )
    .map_err(tree_error)?;
    tree_account.set_fee_schedule(fees);
    Ok(())
}
