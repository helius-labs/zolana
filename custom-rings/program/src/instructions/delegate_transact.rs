use pinocchio::{AccountView, Address, ProgramResult};
use zolana_account_checks::AccountIterator;

use crate::{
    error::CustomRingError,
    instructions::{
        loader::load_delegate,
        transact::{TransactControls, TransactRail},
    },
};

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

    // Auditor decryption grants no signing authority.
    let expected = load_delegate(program_id, delegate_account)?
        .ok_or(CustomRingError::DelegateDisabled)?
        .delegate;
    if !delegate.is_signer() || delegate.address() != &expected {
        return Err(CustomRingError::UnauthorizedDelegate.into());
    }
    TransactRail::Delegate.verify_and_forward(
        TransactControls {
            program_id,
            config_account,
            cosigner_account,
            cosigner,
        },
        iter,
        data,
    )
}
