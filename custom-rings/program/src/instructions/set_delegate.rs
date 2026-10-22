use custom_ring_interface::{CustomRingError, RingMode, RingProgramConfig};
use pinocchio::{AccountView, Address, ProgramResult};
use zolana_account_checks::AccountIterator;

use crate::instructions::{
    loader::{load_mut, load_registry, UpgradeAuthorityCheck},
    shared::no_data,
};

/// Only the upgrade authority appoints the delegate.
#[inline(never)]
pub fn process_set_delegate_ix(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    no_data(data)?;
    let mut iter = AccountIterator::new(accounts);
    let authority = iter.next_signer("authority")?;
    let config = iter.next_mut("config")?;
    let delegate = iter.next_signer("delegate")?;
    let registry = iter.next_account("registry")?;
    let program = iter.next_account("program")?;
    let program_data = iter.next_account("program_data")?;

    // 1. The program's upgrade authority signs, as for `CreateConfig`.
    UpgradeAuthorityCheck {
        program_id,
        authority,
        program,
        program_data,
    }
    .verify()?;
    // 2. The delegate is permanent for the instructions of the deployed binary.
    let mut config = load_mut::<RingProgramConfig>(program_id, config)?;
    if config.delegate().is_some() {
        return Err(CustomRingError::DelegateAlreadySet.into());
    }
    // 3. An anonymous ring hides the owner a delegate would sign for.
    if config.mode()? == RingMode::Anonymous {
        return Err(CustomRingError::AnonymousRingRefused.into());
    }
    if !config.has_policy() {
        return Err(CustomRingError::DelegateRequiresPolicy.into());
    }
    // 4. Registry mode escrows every output nullifier key in the member registry.
    load_registry(program_id, registry)?;
    config.delegate = *delegate.address();
    config.mode = RingMode::Registry as u8;
    Ok(())
}
