use pinocchio::{error::ProgramError, AccountView, Address};

use crate::error::ShieldedPoolError;

pub struct MutableAddressTreeAccounts<'a> {
    pub signer: &'a AccountView,
    pub tree: &'a AccountView,
}

/// Load + validate the (signer, tree) accounts for an address-tree instruction.
///
/// Ownership semantics:
/// - `expect_owned`: when `true`, the tree account must already be owned by
///   the shielded-pool program (post-init mutation paths).
/// - When `false`, the tree account may be system-owned (pre-init: caller
///   has just allocated via system_program with owner = shielded_pool program).
pub fn load_mutable_address_tree_accounts<'a>(
    program_id: &Address,
    accounts: &'a [AccountView],
    expect_owned: bool,
) -> Result<MutableAddressTreeAccounts<'a>, ProgramError> {
    if accounts.len() < 2 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }

    let signer = &accounts[0];
    let tree = &accounts[1];

    if !signer.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if !tree.is_writable() {
        return Err(ShieldedPoolError::InvalidAddressTreeAccounts.into());
    }
    if expect_owned && !tree.owned_by(program_id) {
        return Err(ShieldedPoolError::InvalidAddressTreeAccounts.into());
    }

    Ok(MutableAddressTreeAccounts { signer, tree })
}

pub struct MutableStateTreeAccounts<'a> {
    pub signer: &'a AccountView,
    pub tree: &'a AccountView,
}

pub fn load_mutable_state_tree_accounts<'a>(
    program_id: &Address,
    accounts: &'a [AccountView],
    expect_owned: bool,
) -> Result<MutableStateTreeAccounts<'a>, ProgramError> {
    if accounts.len() < 2 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }

    let signer = &accounts[0];
    let tree = &accounts[1];

    if !signer.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if !tree.is_writable() {
        return Err(ShieldedPoolError::InvalidStateTreeAccounts.into());
    }
    if expect_owned && !tree.owned_by(program_id) {
        return Err(ShieldedPoolError::InvalidStateTreeAccounts.into());
    }

    Ok(MutableStateTreeAccounts { signer, tree })
}
