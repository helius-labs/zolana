use bytemuck::from_bytes;
use pinocchio::{account::Ref, error::ProgramError, AccountView, Address};
use solana_loader_v3_interface::state::UpgradeableLoaderState;
use zolana_interface::custom_ring::{ReaderKeyBytes, ReaderRecord, RingProgramConfig};
use zolana_interface::{BPF_LOADER_UPGRADEABLE_ID, SHIELDED_POOL_PROGRAM_ID};

use crate::{error::CustomRingError, instructions::shared::PdaCheck, state::Account};

/// Loads only the canonical config PDA and stored bump.
#[inline(always)]
pub fn load_config(account: &AccountView) -> Result<Ref<'_, RingProgramConfig>, ProgramError> {
    let bump = PdaCheck {
        address: account.address(),
        seeds: &[RingProgramConfig::SEED],
        mismatch: CustomRingError::InvalidConfigPda,
    }
    .verify()?;
    let config = load_account::<RingProgramConfig>(account)?;
    if config.bump != bump {
        return Err(CustomRingError::InvalidConfigPda.into());
    }
    Ok(config)
}

#[inline(always)]
pub fn load_authorized_config<'a>(
    config: &'a AccountView,
    authority: &AccountView,
) -> Result<Ref<'a, RingProgramConfig>, ProgramError> {
    let config = load_config(config)?;
    if authority.address() != &config.authority {
        return Err(CustomRingError::UnauthorizedAuthority.into());
    }
    Ok(config)
}

#[inline(always)]
pub fn load_reader_record<'a>(
    account: &'a AccountView,
    reader: &ReaderKeyBytes,
) -> Result<Ref<'a, ReaderRecord>, ProgramError> {
    let record = load_account::<ReaderRecord>(account)?;
    let seed_hash = ReaderRecord::seed_hash(reader).map_err(|_| CustomRingError::HashingFailed)?;
    let bump = PdaCheck {
        address: account.address(),
        seeds: &[ReaderRecord::SEED, &seed_hash],
        mismatch: CustomRingError::InvalidReaderRecord,
    }
    .verify()?;
    if record.reader != *reader || record.bump != bump {
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

#[must_use]
pub(crate) struct UpgradeAuthorityCheck<'a> {
    pub authority: &'a AccountView,
    pub program: &'a AccountView,
    pub program_data: &'a AccountView,
}

impl UpgradeAuthorityCheck<'_> {
    pub fn verify(self) -> Result<(), ProgramError> {
        if self.program.address() != &crate::ID {
            return Err(CustomRingError::UnauthorizedInitializer.into());
        }
        if self.program.owner().as_array() != &BPF_LOADER_UPGRADEABLE_ID {
            return Err(CustomRingError::UnauthorizedInitializer.into());
        }
        let program_state = self
            .program
            .try_borrow()
            .map_err(|_| ProgramError::AccountBorrowFailed)?;
        let Some(UpgradeableLoaderState::Program {
            programdata_address,
        }) = decode_loader_state(&program_state)
        else {
            return Err(CustomRingError::UnauthorizedInitializer.into());
        };
        if self.program_data.address().as_array() != programdata_address.as_array()
            || self.program_data.owner().as_array() != &BPF_LOADER_UPGRADEABLE_ID
        {
            return Err(CustomRingError::UnauthorizedInitializer.into());
        }
        let program_data_state = self
            .program_data
            .try_borrow()
            .map_err(|_| ProgramError::AccountBorrowFailed)?;
        let Some(UpgradeableLoaderState::ProgramData {
            upgrade_authority_address,
            ..
        }) = decode_loader_state(&program_data_state)
        else {
            return Err(CustomRingError::UnauthorizedInitializer.into());
        };
        if upgrade_authority_address.map(|key| key.to_bytes())
            != Some(*self.authority.address().as_array())
        {
            return Err(CustomRingError::UnauthorizedInitializer.into());
        }
        Ok(())
    }
}

#[inline(always)]
fn load_account<T: Account>(account: &AccountView) -> Result<Ref<'_, T>, ProgramError> {
    if !account.owned_by(&crate::ID) {
        return Err(T::NOT_INITIALIZED.into());
    }
    let data = account.try_borrow().map_err(|_| T::NOT_INITIALIZED)?;
    if data.len() != T::SIZE {
        return Err(T::NOT_INITIALIZED.into());
    }
    // Length is checked above and each account is align 1, so this cannot panic.
    let value = Ref::map(data, |data| from_bytes::<T>(data));
    if value.discriminator() != T::DISCRIMINATOR {
        return Err(T::NOT_INITIALIZED.into());
    }
    Ok(value)
}

fn decode_loader_state(data: &[u8]) -> Option<UpgradeableLoaderState> {
    bincode::serde::decode_from_slice(data, bincode::config::legacy())
        .ok()
        .map(|(state, _)| state)
}
