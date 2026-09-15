use bytemuck::{from_bytes, from_bytes_mut};
use custom_ring_interface::{CoSigner, Delegate, PolicyConfig, SpendWindow, HEAD_MAP_CAPACITY};
use custom_ring_interface::{ReadAccessRecord, ReaderKeyBytes, RingProgramConfig};
use pinocchio::{
    account::{Ref, RefMut},
    error::ProgramError,
    AccountView, Address,
};
use solana_loader_v3_interface::state::UpgradeableLoaderState;
use zolana_interface::{BPF_LOADER_UPGRADEABLE_ID, SHIELDED_POOL_PROGRAM_ID};

use crate::{
    error::CustomRingError,
    instructions::shared::PdaCheck,
    state::{Account, AppendRoot},
};

/// Loads only the canonical config PDA and stored bump.
#[inline(always)]
pub fn load_config<'a>(
    program_id: &Address,
    account: &'a AccountView,
) -> Result<Ref<'a, RingProgramConfig>, ProgramError> {
    let config = load_account::<RingProgramConfig>(program_id, account)?;
    PdaCheck {
        program_id,
        address: account.address(),
        seeds: &[RingProgramConfig::SEED],
        mismatch: CustomRingError::InvalidConfigPda,
    }
    .verify_stored_bump(config.bump)?;
    Ok(config)
}

#[inline(always)]
pub fn load_authorized_config<'a>(
    program_id: &Address,
    config: &'a AccountView,
    authority: &AccountView,
) -> Result<Ref<'a, RingProgramConfig>, ProgramError> {
    let config = load_config(program_id, config)?;
    if authority.address() != &config.authority {
        return Err(CustomRingError::UnauthorizedAuthority.into());
    }
    Ok(config)
}

#[inline(always)]
pub fn load_policy_config<'a>(
    program_id: &Address,
    account: &'a AccountView,
) -> Result<Ref<'a, PolicyConfig>, ProgramError> {
    let config = load_account::<PolicyConfig>(program_id, account)?;
    PdaCheck {
        program_id,
        address: account.address(),
        seeds: &[PolicyConfig::SEED],
        mismatch: CustomRingError::InvalidPolicyConfigPda,
    }
    .verify_stored_bump(config.bump)?;
    Ok(config)
}

/// `Ok(None)` for the canonical address with no account.
pub(crate) struct OptionalPda<'a> {
    pub program_id: &'a Address,
    pub seeds: &'a [&'a [u8]],
    pub mismatch: CustomRingError,
}

impl<'a> OptionalPda<'a> {
    #[inline(always)]
    pub fn load<'acc, T: Account>(
        self,
        account: &'acc AccountView,
    ) -> Result<Option<Ref<'acc, T>>, ProgramError> {
        if account.data_len() == 0 {
            self.check(account.address()).verify()?;
            return Ok(None);
        }
        let value = load_account::<T>(self.program_id, account)?;
        self.check(account.address())
            .verify_stored_bump(value.bump())?;
        Ok(Some(value))
    }

    #[inline(always)]
    pub fn load_mut<'acc, T: Account>(
        self,
        account: &'acc mut AccountView,
    ) -> Result<Option<RefMut<'acc, T>>, ProgramError> {
        let address = *account.address();
        if account.data_len() == 0 {
            self.check(&address).verify()?;
            return Ok(None);
        }
        let value = load_account_mut::<T>(self.program_id, account)?;
        self.check(&address).verify_stored_bump(value.bump())?;
        Ok(Some(value))
    }

    fn check<'b>(&'b self, address: &'b Address) -> PdaCheck<'b> {
        PdaCheck {
            program_id: self.program_id,
            address,
            seeds: self.seeds,
            mismatch: self.mismatch,
        }
    }
}

#[inline(always)]
pub fn load_cosigner<'a>(
    program_id: &Address,
    account: &'a AccountView,
) -> Result<Option<Ref<'a, CoSigner>>, ProgramError> {
    cosigner_pda(program_id).load(account)
}

#[inline(always)]
pub fn load_cosigner_mut<'a>(
    program_id: &Address,
    account: &'a mut AccountView,
) -> Result<Option<RefMut<'a, CoSigner>>, ProgramError> {
    cosigner_pda(program_id).load_mut(account)
}

fn cosigner_pda(program_id: &Address) -> OptionalPda<'_> {
    OptionalPda {
        program_id,
        seeds: &[CoSigner::SEED],
        mismatch: CustomRingError::InvalidCoSigner,
    }
}

#[inline(always)]
pub fn load_delegate<'a>(
    program_id: &Address,
    account: &'a AccountView,
) -> Result<Option<Ref<'a, Delegate>>, ProgramError> {
    OptionalPda {
        program_id,
        seeds: &[Delegate::SEED],
        mismatch: CustomRingError::InvalidDelegate,
    }
    .load(account)
}

#[inline(always)]
pub fn load_spend_window<'a>(
    program_id: &Address,
    account: &'a AccountView,
    mint: &Address,
) -> Result<Option<Ref<'a, SpendWindow>>, ProgramError> {
    let seeds = [SpendWindow::SEED, mint.as_array()];
    let window = spend_window_pda(program_id, &seeds).load::<SpendWindow>(account)?;
    check_window_mint(window.as_deref(), mint)?;
    Ok(window)
}

#[inline(always)]
pub fn load_spend_window_mut<'a>(
    program_id: &Address,
    account: &'a mut AccountView,
    mint: &Address,
) -> Result<Option<RefMut<'a, SpendWindow>>, ProgramError> {
    let seeds = [SpendWindow::SEED, mint.as_array()];
    let window = spend_window_pda(program_id, &seeds).load_mut::<SpendWindow>(account)?;
    check_window_mint(window.as_deref(), mint)?;
    Ok(window)
}

fn spend_window_pda<'a>(program_id: &'a Address, seeds: &'a [&'a [u8]; 2]) -> OptionalPda<'a> {
    OptionalPda {
        program_id,
        seeds,
        mismatch: CustomRingError::InvalidSpendWindow,
    }
}

fn check_window_mint(window: Option<&SpendWindow>, mint: &Address) -> Result<(), ProgramError> {
    if window.is_some_and(|window| window.mint != *mint) {
        return Err(CustomRingError::InvalidSpendWindow.into());
    }
    Ok(())
}

pub(crate) fn load_append_root_mut<'a, T: AppendRoot>(
    program_id: &Address,
    account: &'a mut AccountView,
) -> Result<RefMut<'a, T>, ProgramError> {
    let address = *account.address();
    let root = load_account_mut::<T>(program_id, account)?;
    PdaCheck {
        program_id,
        address: &address,
        seeds: &[T::SEED],
        mismatch: T::NOT_INITIALIZED,
    }
    .verify_stored_bump(root.bump())?;
    if root.next_index() == 0 || root.next_index() > HEAD_MAP_CAPACITY {
        return Err(T::CURSOR.into());
    }
    Ok(root)
}

#[inline(always)]
pub fn load_read_access_record<'a>(
    program_id: &Address,
    account: &'a AccountView,
    reader: &ReaderKeyBytes,
) -> Result<Ref<'a, ReadAccessRecord>, ProgramError> {
    let record = load_account::<ReadAccessRecord>(program_id, account)?;
    let seed_hash =
        ReadAccessRecord::seed_hash(reader).map_err(|_| CustomRingError::HashingFailed)?;
    let bump = PdaCheck {
        program_id,
        address: account.address(),
        seeds: &[ReadAccessRecord::SEED, &seed_hash],
        mismatch: CustomRingError::InvalidReadAccessRecord,
    }
    .verify()?;
    if record.reader != *reader || record.bump != bump {
        return Err(CustomRingError::InvalidReadAccessRecord.into());
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
    pub program_id: &'a Address,
    pub authority: &'a AccountView,
    pub program: &'a AccountView,
    pub program_data: &'a AccountView,
}

impl UpgradeAuthorityCheck<'_> {
    pub fn verify(self) -> Result<(), ProgramError> {
        if self.program.address() != self.program_id {
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
fn load_account<'a, T: Account>(
    program_id: &Address,
    account: &'a AccountView,
) -> Result<Ref<'a, T>, ProgramError> {
    check_account::<T>(program_id, account)?;
    let data = account.try_borrow().map_err(|_| T::NOT_INITIALIZED)?;
    // Length is checked above and each account is align 1, so this cannot panic.
    let value = Ref::map(data, |data| from_bytes::<T>(data));
    if value.discriminator() != T::DISCRIMINATOR {
        return Err(T::NOT_INITIALIZED.into());
    }
    Ok(value)
}

#[inline(always)]
fn load_account_mut<'a, T: Account>(
    program_id: &Address,
    account: &'a mut AccountView,
) -> Result<RefMut<'a, T>, ProgramError> {
    check_account::<T>(program_id, account)?;
    let data = account.try_borrow_mut().map_err(|_| T::NOT_INITIALIZED)?;
    let value = RefMut::map(data, |data| from_bytes_mut::<T>(data));
    if value.discriminator() != T::DISCRIMINATOR {
        return Err(T::NOT_INITIALIZED.into());
    }
    Ok(value)
}

#[inline(always)]
fn check_account<T: Account>(
    program_id: &Address,
    account: &AccountView,
) -> Result<(), CustomRingError> {
    if !account.owned_by(program_id) || account.data_len() != T::SIZE {
        return Err(T::NOT_INITIALIZED);
    }
    Ok(())
}

fn decode_loader_state(data: &[u8]) -> Option<UpgradeableLoaderState> {
    bincode::serde::decode_from_slice(data, bincode::config::legacy())
        .ok()
        .map(|(state, _)| state)
}
