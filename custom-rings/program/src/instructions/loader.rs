use custom_ring_interface::{
    CustomRingError, MemberRegistry, RecordQueue, RingAccount, RingProgramConfig,
};
use pinocchio::{
    account::{Ref, RefMut},
    address::address_eq,
    error::ProgramError,
    AccountView, Address, ProgramResult,
};
use solana_loader_v3_interface::state::UpgradeableLoaderState;
use zolana_interface::{
    state::discriminator::TREE_ACCOUNT_DISCRIMINATOR, BPF_LOADER_UPGRADEABLE_ID,
    SHIELDED_POOL_PROGRAM_ID,
};
use zolana_tree::TreeAccount;

/// Owner and discriminator suffice, accounts are created only at their canonical PDA.
#[inline(always)]
pub fn load<'a, T: RingAccount>(
    program_id: &Address,
    account: &'a AccountView,
) -> Result<Ref<'a, T>, ProgramError> {
    if !account.owned_by(program_id) {
        return Err(T::INVALID.into());
    }
    let data = account.try_borrow().map_err(|_| T::INVALID)?;
    Ref::filter_map(data, T::from_data).map_err(|_| T::INVALID.into())
}

#[inline(always)]
pub fn load_mut<'a, T: RingAccount>(
    program_id: &Address,
    account: &'a mut AccountView,
) -> Result<RefMut<'a, T>, ProgramError> {
    if !account.owned_by(program_id) {
        return Err(T::INVALID.into());
    }
    let data = account.try_borrow_mut().map_err(|_| T::INVALID)?;
    RefMut::filter_map(data, T::from_data_mut).map_err(|_| T::INVALID.into())
}

/// The ring config, its mode byte known.
#[inline(always)]
pub fn load_config<'a>(
    program_id: &Address,
    account: &'a AccountView,
) -> Result<Ref<'a, RingProgramConfig>, ProgramError> {
    load(program_id, account)
}

/// The config whose authority is `authority`, the processor checks the signature.
#[inline(always)]
pub fn load_authorized_config<'a>(
    program_id: &Address,
    config: &'a AccountView,
    authority: &AccountView,
) -> Result<Ref<'a, RingProgramConfig>, ProgramError> {
    let config = load_config(program_id, config)?;
    check_authority(&config, authority)?;
    Ok(config)
}

#[inline(always)]
pub fn load_authorized_config_mut<'a>(
    program_id: &Address,
    config: &'a mut AccountView,
    authority: &AccountView,
) -> Result<RefMut<'a, RingProgramConfig>, ProgramError> {
    let config = load_mut::<RingProgramConfig>(program_id, config)?;
    check_authority(&config, authority)?;
    Ok(config)
}

fn check_authority(config: &RingProgramConfig, authority: &AccountView) -> ProgramResult {
    if authority.address() != &config.authority {
        return Err(CustomRingError::UnauthorizedAuthority.into());
    }
    Ok(())
}

#[inline(always)]
pub fn load_registry<'a>(
    program_id: &Address,
    account: &'a AccountView,
) -> Result<Ref<'a, MemberRegistry>, ProgramError> {
    load(program_id, account)
}

#[inline(always)]
pub fn load_registry_mut<'a>(
    program_id: &Address,
    account: &'a mut AccountView,
) -> Result<RefMut<'a, MemberRegistry>, ProgramError> {
    load_mut(program_id, account)
}

/// A registry of another ring, the `[b"members"]` PDA of the program owning it.
pub fn load_curator_registry(
    account: &AccountView,
) -> Result<Ref<'_, MemberRegistry>, ProgramError> {
    let invalid = CustomRingError::InvalidCuratorRegistry;
    let curator_program = *account.owner();
    let data = account.try_borrow().map_err(|_| invalid)?;
    let registry = Ref::filter_map(data, MemberRegistry::from_data).map_err(|_| invalid)?;
    let address = Address::derive_address(
        &[MemberRegistry::SEED],
        Some(registry.bump),
        &curator_program,
    );
    if !address_eq(account.address(), &address) {
        return Err(invalid.into());
    }
    Ok(registry)
}

#[inline(always)]
pub fn load_queue_mut<'a>(
    program_id: &Address,
    account: &'a mut AccountView,
) -> Result<RefMut<'a, RecordQueue>, ProgramError> {
    load_mut(program_id, account)
}

/// The borrow ends here, the tree may be one the SPP CPI writes.
pub fn load_spp_tree_root(account: &mut AccountView, index: u16) -> Result<[u8; 32], ProgramError> {
    let missing = CustomRingError::FirstContactRootMissing;
    if !account.owned_by(&Address::from(SHIELDED_POOL_PROGRAM_ID)) {
        return Err(missing.into());
    }
    let address = account.address().to_bytes();
    let mut data = account.try_borrow_mut().map_err(|_| missing)?;
    if data.first() != Some(&TREE_ACCOUNT_DISCRIMINATOR) {
        return Err(missing.into());
    }
    let tree = TreeAccount::from_bytes(&mut data, address).map_err(|_| missing)?;
    if tree.is_paused() {
        return Err(CustomRingError::FirstContactTreePaused.into());
    }
    tree.get_utxo_tree_root(index).map_err(|_| missing.into())
}

/// The shielded pool by address, its account position differs per forwarded layout.
#[inline(always)]
pub fn validate_spp_program(accounts: &[AccountView]) -> ProgramResult {
    let spp_id = Address::from(SHIELDED_POOL_PROGRAM_ID);
    if !accounts
        .iter()
        .any(|account| account.address() == &spp_id && account.executable())
    {
        return Err(CustomRingError::InvalidShieldedPoolProgram.into());
    }
    Ok(())
}

/// The forward raises the ring PDA to a signer, an account SPP debits signs the outer instruction.
pub fn check_funding_signer(
    accounts: &[AccountView],
    index: usize,
) -> Result<&AccountView, ProgramError> {
    let funder = accounts
        .get(index)
        .ok_or(ProgramError::NotEnoughAccountKeys)?;
    if !funder.is_signer() {
        return Err(CustomRingError::MissingFundingSigner.into());
    }
    Ok(funder)
}

pub fn check_co_signer(account: &AccountView, expected: &Address) -> ProgramResult {
    if !account.is_signer() {
        return Err(CustomRingError::MissingCoSigner.into());
    }
    if account.address() != expected {
        return Err(CustomRingError::UnauthorizedCoSigner.into());
    }
    Ok(())
}

/// Passes only this program's nonzero loader-v3 upgrade authority.
#[must_use]
pub struct UpgradeAuthorityCheck<'a> {
    pub program_id: &'a Address,
    pub authority: &'a AccountView,
    pub program: &'a AccountView,
    pub program_data: &'a AccountView,
}

impl UpgradeAuthorityCheck<'_> {
    pub fn verify(self) -> ProgramResult {
        let unauthorized = CustomRingError::UnauthorizedInitializer;
        if self.program.address() != self.program_id
            || self.program.owner().as_array() != &BPF_LOADER_UPGRADEABLE_ID
        {
            return Err(unauthorized.into());
        }
        let Some(UpgradeableLoaderState::Program {
            programdata_address,
        }) = loader_state(self.program)?
        else {
            return Err(unauthorized.into());
        };
        if self.program_data.address().as_array() != programdata_address.as_array()
            || self.program_data.owner().as_array() != &BPF_LOADER_UPGRADEABLE_ID
        {
            return Err(unauthorized.into());
        }
        let Some(UpgradeableLoaderState::ProgramData {
            upgrade_authority_address: Some(upgrade_authority),
            ..
        }) = loader_state(self.program_data)?
        else {
            return Err(unauthorized.into());
        };
        let upgrade_authority = upgrade_authority.to_bytes();
        if upgrade_authority == [0; 32] || upgrade_authority != self.authority.address().to_bytes()
        {
            return Err(unauthorized.into());
        }
        Ok(())
    }
}

/// bincode reads only the enum, the trailing ELF bytes of program data stay untouched.
fn loader_state(account: &AccountView) -> Result<Option<UpgradeableLoaderState>, ProgramError> {
    let data = account
        .try_borrow()
        .map_err(|_| ProgramError::AccountBorrowFailed)?;
    Ok(
        bincode::serde::decode_from_slice(&data, bincode::config::legacy())
            .ok()
            .map(|(state, _)| state),
    )
}
