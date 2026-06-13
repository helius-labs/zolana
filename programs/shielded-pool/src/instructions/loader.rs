use pinocchio::{error::ProgramError, AccountView, Address};

use crate::error::ShieldedPoolError;

pub struct MutableTreeAccounts<'a> {
    pub signer: &'a AccountView,
    pub tree: &'a mut AccountView,
}

/// Mutable view of a validated account's data buffer.
///
/// This is the single place that performs `borrow_unchecked_mut`; instruction
/// handlers call it instead of writing their own `unsafe` block, so the safety
/// rationale lives here rather than being copy-pasted across call sites.
///
/// SAFETY: `account` must be a writable account the caller already validated
/// (e.g. via [`load_mutable_tree_accounts`]) and must not be aliased by
/// any other live borrow while the returned slice is in scope. Each pinocchio
/// account owns a distinct data buffer and these handlers never borrow the same
/// account twice, so the unchecked borrow is sound.
pub fn account_data_mut(account: &mut AccountView) -> &mut [u8] {
    // SAFETY: upheld by the caller per the function contract above.
    unsafe { account.borrow_unchecked_mut() }
}

/// Load + validate the (signer, tree) accounts for any pool-tree instruction.
///
/// - `expect_owned = true`: the tree account must already be owned by this
///   program. The standard pre-create flow (caller invokes
///   system_program::create_account with `owner = shielded_pool_program_id`)
///   means this also holds before our `create_tree` runs.
pub fn load_mutable_tree_accounts<'a>(
    program_id: &Address,
    accounts: &'a mut [AccountView],
    expect_owned: bool,
) -> Result<MutableTreeAccounts<'a>, ProgramError> {
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
        return Err(ShieldedPoolError::InvalidTreeAccounts.into());
    }
    if expect_owned && !tree.owned_by(program_id) {
        return Err(ShieldedPoolError::InvalidTreeAccounts.into());
    }

    Ok(MutableTreeAccounts { signer, tree })
}
