use borsh::BorshDeserialize;
use pinocchio::{error::ProgramError, AccountView, ProgramResult};
use zolana_account_checks::{checks::check_owner, AccountIterator};
use zolana_interface::{
    error::ShieldedPoolError,
    instruction::CreateTreeData,
    state::{address_tree_params, discriminator::TREE_ACCOUNT_DISCRIMINATOR, STATE_HEIGHT},
};
use zolana_tree::TreeAccount;

use crate::instructions::protocol_config::loader::load_protocol_config;

pub fn process_create_tree(accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    let data = CreateTreeData::try_from_slice(data)
        .map_err(|_| ShieldedPoolError::InvalidInstructionData)?;
    let mut iter = AccountIterator::new(accounts);
    let authority = iter.next_signer("authority")?;
    let protocol_config = iter.next_account("protocol_config")?;
    let tree = iter.next_mut("tree")?;

    let config = load_protocol_config(protocol_config)?;
    if !config.allows_permissionless_tree_creation()
        && config
            .check_tree_creation_authority(authority.address())
            .is_err()
    {
        return Err(ShieldedPoolError::UnauthorizedCaller.into());
    }
    drop(config);
    check_owner(crate::ID.as_array(), tree)?;

    if tree.data_len() != TreeAccount::account_size() {
        return Err(ShieldedPoolError::InvalidTreeAccounts.into());
    }

    let tree_pubkey = tree.address().to_bytes();
    let mut tree_data = tree
        .try_borrow_mut()
        .map_err(|_| ProgramError::AccountBorrowFailed)?;

    TreeAccount::init(
        &mut tree_data,
        TREE_ACCOUNT_DISCRIMINATOR,
        STATE_HEIGHT as u8,
        data.owner,
        tree_pubkey,
        address_tree_params(),
    )
    .map_err(|_| ShieldedPoolError::InvalidTreeAccounts)?;
    Ok(())
}
