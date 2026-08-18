use bytemuck::from_bytes;
use pinocchio::{account::Ref, error::ProgramError, AccountView, Address};
use zolana_interface::SHIELDED_POOL_PROGRAM_ID;

use crate::{error::CustomRingError, state::RingProgramConfig};

/// Load the ring config read-only: owned by this program, exact length, and
/// carrying the config discriminator.
///
/// The canonical PDA derivation is checked once, at creation; access control
/// here relies on the stored `authority` rather than on the derivation, so later
/// loads need only ownership plus the discriminator.
#[inline(always)]
pub fn load_config(account: &AccountView) -> Result<Ref<'_, RingProgramConfig>, ProgramError> {
    if !account.owned_by(&crate::ID) {
        return Err(CustomRingError::ConfigNotInitialized.into());
    }
    let data = account
        .try_borrow()
        .map_err(|_| CustomRingError::ConfigNotInitialized)?;
    if data.len() != RingProgramConfig::SIZE {
        return Err(CustomRingError::ConfigNotInitialized.into());
    }
    // Length is checked above and the struct is align 1, so this cannot panic.
    let config = Ref::map(data, |data| from_bytes::<RingProgramConfig>(data));
    if !config.has_discriminator() {
        return Err(CustomRingError::ConfigNotInitialized.into());
    }
    Ok(config)
}

/// Require the shielded-pool program to be among `accounts` and executable.
///
/// The lookup scans by address instead of indexing a fixed slot: only SPP's
/// `transact` layout pins the program account at index 3, while the deposit and
/// ring-config layouts place it elsewhere, so a single index would be wrong for
/// at least one forwarded instruction (same reasoning as
/// `program-tests/ring-test-program`).
#[inline(always)]
pub fn validate_spp_program(accounts: &[AccountView]) -> Result<(), ProgramError> {
    let spp_id = Address::from(SHIELDED_POOL_PROGRAM_ID);
    let spp = accounts
        .iter()
        .find(|account| account.address() == &spp_id)
        .ok_or(CustomRingError::InvalidShieldedPoolProgram)?;
    if !spp.executable() {
        return Err(CustomRingError::InvalidShieldedPoolProgram.into());
    }
    Ok(())
}
