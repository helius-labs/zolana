use pinocchio::{error::ProgramError, AccountView, Address};

use crate::error::ShieldedPoolError;

pub struct MutablePoolTreeAccounts<'a> {
    pub signer: &'a AccountView,
    pub tree: &'a AccountView,
}

/// Load + validate the (signer, tree) accounts for any pool-tree instruction.
///
/// - `expect_owned = true`: the tree account must already be owned by this
///   program. The standard pre-create flow (caller invokes
///   system_program::create_account with `owner = shielded_pool_program_id`)
///   means this also holds before our `create_pool_tree` runs.
pub fn load_mutable_pool_tree_accounts<'a>(
    program_id: &Address,
    accounts: &'a [AccountView],
    expect_owned: bool,
) -> Result<MutablePoolTreeAccounts<'a>, ProgramError> {
    if accounts.len() < 2 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    let signer = &accounts[0];
    let tree = &accounts[1];

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
