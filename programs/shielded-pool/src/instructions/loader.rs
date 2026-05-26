use pinocchio::{error::ProgramError, AccountView, Address};

use crate::error::ShieldedPoolError;

pub struct MutablePoolTreeAccounts<'a> {
    pub signer: &'a AccountView,
    pub tree: &'a mut AccountView,
}

/// Load + validate the (signer, tree) accounts for any pool-tree instruction.
///
/// - `expect_owned = true`: the tree account must already be owned by this
///   program. The standard pre-create flow (caller invokes
///   system_program::create_account with `owner = shielded_pool_program_id`)
///   means this also holds before our `create_pool_tree` runs.
pub fn load_mutable_pool_tree_accounts<'a>(
    program_id: &Address,
    accounts: &'a mut [AccountView],
    expect_owned: bool,
) -> Result<MutablePoolTreeAccounts<'a>, ProgramError> {
    if accounts.len() < 2 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    // Split so we can hand the caller a `&AccountView` and a `&mut
    // AccountView` simultaneously without aliasing.
    let (head, tail) = accounts.split_at_mut(1);
    let signer = &head[0];
    let tree = &mut tail[0];

    if !signer.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if !tree.is_writable() {
        return Err(ShieldedPoolError::InvalidPoolTreeAccounts.into());
    }
    if expect_owned && !tree.owned_by(program_id) {
        return Err(ShieldedPoolError::InvalidPoolTreeAccounts.into());
    }

    Ok(MutablePoolTreeAccounts { signer, tree })
}
