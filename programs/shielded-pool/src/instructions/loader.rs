use pinocchio::{error::ProgramError, AccountView};

use crate::error::ShieldedPoolError;

pub struct MutableAddressTreeAccounts<'a> {
    pub signer: &'a AccountView,
    pub tree: &'a AccountView,
    pub queue: &'a AccountView,
}

pub fn load_mutable_address_tree_accounts(
    accounts: &[AccountView],
) -> Result<MutableAddressTreeAccounts<'_>, ProgramError> {
    if accounts.len() < 3 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }

    let signer = &accounts[0];
    let tree = &accounts[1];
    let queue = &accounts[2];

    if !signer.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if !tree.is_writable() || !queue.is_writable() || tree.address() == queue.address() {
        return Err(ShieldedPoolError::InvalidAddressTreeAccounts.into());
    }

    Ok(MutableAddressTreeAccounts {
        signer,
        tree,
        queue,
    })
}

pub struct MutableStateTreeAccounts<'a> {
    pub signer: &'a AccountView,
    pub tree: &'a AccountView,
}

pub fn load_mutable_state_tree_accounts(
    accounts: &[AccountView],
) -> Result<MutableStateTreeAccounts<'_>, ProgramError> {
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

    Ok(MutableStateTreeAccounts { signer, tree })
}
