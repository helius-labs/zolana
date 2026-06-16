use pinocchio::{AccountView, Address, ProgramResult};
use zolana_interface::{
    instruction::CreateTreeData,
    state::{address_tree_params, discriminator::TREE_ACCOUNT_DISCRIMINATOR, STATE_HEIGHT},
};
use zolana_tree::TreeAccount;

use super::verify::verify;
use crate::{error::ShieldedPoolError, instructions::loader};

pub fn process_create_tree(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: CreateTreeData,
) -> ProgramResult {
    let verified = verify(program_id, accounts)?;
    let tree_pubkey = verified.tree.address().to_bytes();
    let bytes = loader::account_data_mut(verified.tree);

    // `init` refuses to re-initialize: it errors unless the `state` byte is
    // `UNINITIALIZED`, so a second create_tree cannot clobber a live tree.
    TreeAccount::init(
        bytes,
        TREE_ACCOUNT_DISCRIMINATOR,
        STATE_HEIGHT as u8,
        data.owner,
        tree_pubkey,
        address_tree_params(),
    )
    .map_err(|_| ShieldedPoolError::InvalidTreeAccounts)?;
    Ok(())
}
