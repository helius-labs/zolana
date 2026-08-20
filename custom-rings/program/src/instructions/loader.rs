use bytemuck::from_bytes;
use pinocchio::{account::Ref, error::ProgramError, AccountView, Address};
use solana_loader_v3_interface::state::UpgradeableLoaderState;
use zolana_interface::{BPF_LOADER_UPGRADEABLE_ID, SHIELDED_POOL_PROGRAM_ID};

use crate::{
    error::CustomRingError,
    state::{ReaderRecord, RingProgramConfig},
};

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

/// Load a reader record read-only: owned by this program, exact length, and
/// carrying the record discriminator. The length check also refuses the config
/// account, so a revoke cannot close it.
#[inline(always)]
pub fn load_reader_record(account: &AccountView) -> Result<Ref<'_, ReaderRecord>, ProgramError> {
    if !account.owned_by(&crate::ID) {
        return Err(CustomRingError::InvalidReaderRecord.into());
    }
    let data = account
        .try_borrow()
        .map_err(|_| CustomRingError::InvalidReaderRecord)?;
    if data.len() != ReaderRecord::SIZE {
        return Err(CustomRingError::InvalidReaderRecord.into());
    }
    // Length is checked above and the struct is align 1, so this cannot panic.
    let record = Ref::map(data, |data| from_bytes::<ReaderRecord>(data));
    if !record.has_discriminator() {
        return Err(CustomRingError::InvalidReaderRecord.into());
    }
    Ok(record)
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

/// Require `authority` to be the program's upgrade authority when the
/// deployment names one.
///
/// The deployment shape gates the check, and an attacker cannot influence the
/// owner or contents of the program's own account. A non-upgradeable
/// deployment skips it, and so does an unset or zeroed upgrade authority
/// (immutable program, LiteSVM, localnet `--bpf-program`). Anything forged
/// (wrong program account, wrong `ProgramData` address or owner, truncated
/// state) fails closed. Renouncing the upgrade authority before `create_config`
/// reopens permissionless init, so a deployment inits before `--final`.
#[inline(always)]
pub fn check_upgrade_authority(
    authority: &AccountView,
    program: &AccountView,
    program_data: &AccountView,
) -> Result<(), ProgramError> {
    if program.address() != &crate::ID {
        return Err(CustomRingError::UnauthorizedInitializer.into());
    }
    if program.owner().as_array() != &BPF_LOADER_UPGRADEABLE_ID {
        return Ok(());
    }
    let program_state = program
        .try_borrow()
        .map_err(|_| ProgramError::AccountBorrowFailed)?;
    let Some(UpgradeableLoaderState::Program {
        programdata_address,
    }) = decode_loader_state(&program_state)
    else {
        return Err(CustomRingError::UnauthorizedInitializer.into());
    };
    if program_data.address().as_array() != programdata_address.as_array()
        || program_data.owner().as_array() != &BPF_LOADER_UPGRADEABLE_ID
    {
        return Err(CustomRingError::UnauthorizedInitializer.into());
    }
    let program_data_state = program_data
        .try_borrow()
        .map_err(|_| ProgramError::AccountBorrowFailed)?;
    let Some(UpgradeableLoaderState::ProgramData {
        upgrade_authority_address,
        ..
    }) = decode_loader_state(&program_data_state)
    else {
        return Err(CustomRingError::UnauthorizedInitializer.into());
    };
    match upgrade_authority_address.map(|key| key.to_bytes()) {
        Some(upgrade_authority)
            if upgrade_authority != [0u8; 32]
                && upgrade_authority != *authority.address().as_array() =>
        {
            Err(CustomRingError::UnauthorizedInitializer.into())
        }
        _ => Ok(()),
    }
}

/// bincode 2.x reads only the enum fields, so the trailing ELF bytecode of a
/// `ProgramData` account is untouched. Malformed state decodes to `None`.
fn decode_loader_state(data: &[u8]) -> Option<UpgradeableLoaderState> {
    bincode::serde::decode_from_slice(data, bincode::config::legacy())
        .ok()
        .map(|(state, _)| state)
}
