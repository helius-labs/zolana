use pinocchio::{error::ProgramError, AccountView, Address};

use crate::{
    error::ShieldedPoolError,
    instructions::{loader::MutableTreeAccounts, protocol_config::processor::read_protocol_config},
};

/// Validate `[authority, protocol_config, tree]`. Tree creation is admin-gated
/// by the authority named in the canonical protocol config.
pub fn verify<'a>(
    program_id: &Address,
    accounts: &'a mut [AccountView],
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

    Ok(MutableTreeAccounts { tree })
}
