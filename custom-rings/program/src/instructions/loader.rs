use custom_ring_interface::{
    CustomRingError, DepositAudit, KeyEscrow, KeyRegistryRoot, PolicyConfig, RingAccount,
    RingProgramConfig, SpendWindow,
};
use pinocchio::{
    account::{Ref, RefMut},
    address::address_eq,
    error::ProgramError,
    AccountView, Address, ProgramResult,
};
use solana_loader_v3_interface::state::UpgradeableLoaderState;
use zolana_account_checks::AccountIterator;
use zolana_interface::{
    instruction::instruction_data::transact::TreeContext,
    state::{discriminator::TREE_ACCOUNT_DISCRIMINATOR, read_tree_id},
    tree_slot::{resolve_tree_slot, TreeSlot},
    BPF_LOADER_UPGRADEABLE_ID, SHIELDED_POOL_PROGRAM_ID,
};
use zolana_tree::TreeAccount;

use crate::instructions::shared::verify_pda;

/// The program's initialized `T`. Accounts are created only at their canonical
/// PDA, so owner and discriminator need no address check.
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

/// `None` for an empty account, which must sit at the canonical address so a
/// stand-in cannot switch an optional control off.
pub fn load_optional<'a, T: RingAccount, const N: usize>(
    program_id: &Address,
    account: &'a AccountView,
    seeds: &[&[u8]; N],
) -> Result<Option<Ref<'a, T>>, ProgramError> {
    if account.data_len() == 0 {
        verify_pda(program_id, account.address(), seeds, T::ADDRESS)?;
        return Ok(None);
    }
    load(program_id, account).map(Some)
}

/// The config whose authority is `authority`, the processor checks the signature.
#[inline(always)]
pub fn load_authorized_config<'a>(
    program_id: &Address,
    config: &'a AccountView,
    authority: &AccountView,
) -> Result<Ref<'a, RingProgramConfig>, ProgramError> {
    let config = load::<RingProgramConfig>(program_id, config)?;
    if authority.address() != &config.authority {
        return Err(CustomRingError::UnauthorizedAuthority.into());
    }
    Ok(config)
}

#[inline(always)]
pub fn load_authorized_config_mut<'a>(
    program_id: &Address,
    config: &'a mut AccountView,
    authority: &AccountView,
) -> Result<RefMut<'a, RingProgramConfig>, ProgramError> {
    let config = load_mut::<RingProgramConfig>(program_id, config)?;
    if authority.address() != &config.authority {
        return Err(CustomRingError::UnauthorizedAuthority.into());
    }
    Ok(config)
}

/// A foreign-owned empty setting cannot switch the requirement off either.
pub fn load_deposit_audit<'a>(
    program_id: &Address,
    account: &'a AccountView,
) -> Result<Option<Ref<'a, DepositAudit>>, ProgramError> {
    if account.data_len() == 0 && !pinocchio_system::check_id(account.owner()) {
        return Err(CustomRingError::InvalidDepositAudit.into());
    }
    load_optional(program_id, account, &[DepositAudit::SEED])
}

/// The mint's window, `None` when its canonical address is empty.
pub fn load_spend_window_mut<'a>(
    program_id: &Address,
    account: &'a mut AccountView,
    mint: &Address,
) -> Result<Option<RefMut<'a, SpendWindow>>, ProgramError> {
    let invalid = CustomRingError::InvalidSpendWindow;
    if account.data_len() == 0 {
        verify_pda(
            program_id,
            account.address(),
            &[SpendWindow::SEED, mint.as_array()],
            invalid,
        )?;
        return Ok(None);
    }
    let window = load_mut::<SpendWindow>(program_id, account)?;
    if window.mint != *mint {
        return Err(invalid.into());
    }
    Ok(Some(window))
}

/// The registry root at `index` a statement binds, `None` with escrow off.
pub fn load_escrow_root(
    program_id: &Address,
    escrow: KeyEscrow,
    index: u8,
    accounts: &mut AccountIterator<'_>,
) -> Result<Option<[u8; 32]>, ProgramError> {
    match escrow {
        KeyEscrow::Off if index != 0 => Err(CustomRingError::InvalidInstructionData.into()),
        KeyEscrow::Off => Ok(None),
        KeyEscrow::Registry => {
            let account = accounts.next_account("key_registry_root")?;
            load::<KeyRegistryRoot>(program_id, account)?
                .root_at(index)
                .map(Some)
                .ok_or_else(|| CustomRingError::StaleKeyRegistryRoot.into())
        }
    }
}

/// A curator's policy config, the `b"policy"` PDA of its owning program on the same address tree.
pub fn load_curator_policy_config<'a>(
    account: &'a AccountView,
    address_tree: &Address,
) -> Result<Ref<'a, PolicyConfig>, ProgramError> {
    let invalid = CustomRingError::InvalidCuratorPolicyConfig;
    let curator_program = account.owner();
    let data = account.try_borrow().map_err(|_| invalid)?;
    let config = Ref::filter_map(data, PolicyConfig::from_data).map_err(|_| invalid)?;
    let address =
        Address::derive_address(&[PolicyConfig::SEED], Some(config.bump), curator_program);
    if !address_eq(account.address(), &address) {
        return Err(invalid.into());
    }
    if !address_eq(&config.address_tree, address_tree) {
        return Err(CustomRingError::CuratorTreeMismatch.into());
    }
    Ok(config)
}

/// The raw id of an SPP tree account, `invalid` for any other account.
pub fn load_spp_tree_id(
    account: &AccountView,
    invalid: CustomRingError,
) -> Result<u16, ProgramError> {
    if !account.owned_by(&Address::from(SHIELDED_POOL_PROGRAM_ID)) {
        return Err(invalid.into());
    }
    let data = account.try_borrow().map_err(|_| invalid)?;
    if data.first() != Some(&TREE_ACCOUNT_DISCRIMINATOR) {
        return Err(invalid.into());
    }
    Ok(read_tree_id(&data).ok_or(invalid)?)
}

/// The borrow ends here, a policy tree may alias a tree the SPP CPI writes.
pub fn load_policy_tree_slot(
    account: &mut AccountView,
    context: &TreeContext,
) -> Result<TreeSlot, ProgramError> {
    let invalid = CustomRingError::InvalidPolicyTrees;
    if !account.owned_by(&Address::from(SHIELDED_POOL_PROGRAM_ID)) {
        return Err(invalid.into());
    }
    let address = account.address().to_bytes();
    let mut data = account.try_borrow_mut().map_err(|_| invalid)?;
    if data.first() != Some(&TREE_ACCOUNT_DISCRIMINATOR) {
        return Err(invalid.into());
    }
    let tree = TreeAccount::from_bytes(&mut data, address).map_err(|_| invalid)?;
    if tree.is_paused() {
        return Err(invalid.into());
    }
    resolve_tree_slot(&tree, context).map_err(|_| CustomRingError::StalePolicyRoot.into())
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

/// Only the nonzero loader-v3 upgrade authority of this program passes, an
/// unset or zero authority and malformed loader state fail closed.
pub fn check_upgrade_authority(
    program_id: &Address,
    authority: &AccountView,
    program: &AccountView,
    program_data: &AccountView,
) -> ProgramResult {
    let unauthorized = CustomRingError::UnauthorizedInitializer;
    if program.address() != program_id || program.owner().as_array() != &BPF_LOADER_UPGRADEABLE_ID {
        return Err(unauthorized.into());
    }
    let Some(UpgradeableLoaderState::Program {
        programdata_address,
    }) = loader_state(program)?
    else {
        return Err(unauthorized.into());
    };
    if program_data.address().as_array() != programdata_address.as_array()
        || program_data.owner().as_array() != &BPF_LOADER_UPGRADEABLE_ID
    {
        return Err(unauthorized.into());
    }
    let Some(UpgradeableLoaderState::ProgramData {
        upgrade_authority_address: Some(upgrade_authority),
        ..
    }) = loader_state(program_data)?
    else {
        return Err(unauthorized.into());
    };
    let upgrade_authority = upgrade_authority.to_bytes();
    if upgrade_authority == [0; 32] || upgrade_authority != authority.address().to_bytes() {
        return Err(unauthorized.into());
    }
    Ok(())
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
