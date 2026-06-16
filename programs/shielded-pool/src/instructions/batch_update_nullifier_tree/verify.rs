use pinocchio::{error::ProgramError, AccountView, Address};
use zolana_interface::instruction::BatchUpdateNullifierTreeData;

use crate::{
    error::ShieldedPoolError,
    instructions::{
        loader::MutableTreeAccounts,
        protocol_config::processor::{assert_tree_not_paused, read_protocol_config},
    },
};

/// Validate `[authority, protocol_config, tree]`. Forester maintenance is a
/// tree write, so it is gated by the protocol authority and the pause bit.
pub fn verify<'a>(
    program_id: &Address,
    accounts: &'a mut [AccountView],
    _data: &BatchUpdateNullifierTreeData,
) -> Result<MutableTreeAccounts<'a>, ProgramError> {
    if accounts.len() < 3 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    let (head, tail) = accounts.split_at_mut(2);
    let authority = &head[0];
    let protocol_config = &head[1];
    let tree = &mut tail[0];

    let config = read_protocol_config(program_id, protocol_config)?;
    if authority.address().as_ref() != config.authority {
        return Err(ShieldedPoolError::UnauthorizedCaller.into());
    }
    if !tree.is_writable() || !tree.owned_by(program_id) {
        return Err(ShieldedPoolError::InvalidTreeAccounts.into());
    }
    assert_tree_not_paused(tree)?;

    Ok(MutableTreeAccounts { tree })
}
