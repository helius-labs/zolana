use custom_ring_interface::{CustomRingError, Delegate};
use pinocchio::{AccountView, Address, ProgramResult};
use zolana_account_checks::AccountIterator;

use crate::instructions::{
    loader::load_optional,
    transact::{Controls, Rail},
};

#[inline(never)]
pub fn process_delegate_transact_ix(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: &[u8],
    kind: custom_ring_interface::PolicyProofKind,
) -> ProgramResult {
    let mut iter = AccountIterator::new(accounts);
    let controls = Controls::next(&mut iter)?;
    let delegate_account = iter.next_account("delegate_pda")?;
    let delegate = iter.next_account("delegate")?;

    // Auditor decryption grants no signing authority.
    let expected = load_optional::<Delegate, 1>(program_id, delegate_account, &[Delegate::SEED])?
        .ok_or(CustomRingError::DelegateDisabled)?
        .delegate;
    if !delegate.is_signer() || delegate.address() != &expected {
        return Err(CustomRingError::UnauthorizedDelegate.into());
    }
    Rail::Delegate.verify_and_forward(program_id, controls, iter, data, kind)
}
