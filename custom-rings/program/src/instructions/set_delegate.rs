use custom_ring_interface::{CustomRingError, RingMode, RingProgramConfig};
use pinocchio::{AccountView, Address, ProgramResult};
use zolana_account_checks::AccountIterator;

use crate::instructions::loader::{load_mut, load_registry, UpgradeAuthorityCheck};

/// Only the upgrade authority appoints the delegate.
#[inline(never)]
pub fn process_set_delegate_ix(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    let delegate: [u8; 32] = data
        .try_into()
        .map_err(|_| CustomRingError::InvalidInstructionData)?;
    if delegate == [0; 32] {
        return Err(CustomRingError::InvalidDelegate.into());
    }
    let mut iter = AccountIterator::new(accounts);
    let authority = iter.next_signer("authority")?;
    let config = iter.next_mut("config")?;
    let registry = iter.next_account("registry")?;
    let program = iter.next_account("program")?;
    let program_data = iter.next_account("program_data")?;

    UpgradeAuthorityCheck {
        program_id,
        authority,
        program,
        program_data,
    }
    .verify()?;
    let mut config = load_mut::<RingProgramConfig>(program_id, config)?;
    // The delegate is permanent for the instructions of the deployed binary.
    if config.delegate().is_some() {
        return Err(CustomRingError::DelegateAlreadySet.into());
    }
    // An anonymous ring hides the owner a delegate would sign for.
    if config.mode()? == RingMode::Anonymous {
        return Err(CustomRingError::AnonymousRingRefused.into());
    }
    if !config.has_policy() {
        return Err(CustomRingError::DelegateRequiresPolicy.into());
    }
    // The delegate recovers nullifier secrets from the records every output key escrows into.
    load_registry(program_id, registry)?;
    config.delegate = Address::new_from_array(delegate);
    config.mode = RingMode::Registry as u8;
    Ok(())
}
