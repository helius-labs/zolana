use pinocchio::{AccountView, Address, ProgramResult};
use zolana_account_checks::AccountIterator;

use crate::{
    error::CustomRingError,
    instructions::{
        loader::load_delegate,
        transact::{verify_and_forward, Rail, TransactControlAccounts},
    },
};

/// Authorizes the appointed delegate through the audited and policy-checked authority path.
#[inline(never)]
pub fn process_delegate_transact_ix(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    let mut iter = AccountIterator::new(accounts);
    iter.next_signer_mut("payer")?;
    let config_account = iter.next_account("config")?;
    let cosigner_account = iter.next_account("cosigner_pda")?;
    let cosigner = iter.next_account("cosigner")?;
    let delegate_account = iter.next_account("delegate_pda")?;
    let delegate = iter.next_account("delegate")?;

    // 1. Authenticate the permanently appointed delegate.
    let expected = load_delegate(program_id, delegate_account)?
        .ok_or(CustomRingError::DelegateDisabled)?
        .delegate;
    if !delegate.is_signer() || delegate.address() != &expected {
        return Err(CustomRingError::UnauthorizedDelegate.into());
    }
    // 2. Preserve audit and list requirements while excluding member outflow accounting.
    verify_and_forward(
        program_id,
        iter,
        TransactControlAccounts {
            config_account,
            cosigner_account,
            cosigner,
        },
        data,
        Rail::Delegate,
    )
}
