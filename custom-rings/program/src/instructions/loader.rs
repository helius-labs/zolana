use custom_ring_interface::{
    CustomRingError, DepositAudit, MemberRegistryRoot, RingAccount, RingMode, RingProgramConfig,
    TAGGED_X25519_KEY_LEN,
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

/// The config of a ring whose auditor key can receive a proven disclosure, copied out.
pub struct AuditedConfig {
    pub auditor_pubkey: [u8; TAGGED_X25519_KEY_LEN],
    pub has_policy: bool,
    pub mode: RingMode,
}

/// Refuses an unknown mode and a legacy auditor key, which no circuit encrypts to.
#[inline(always)]
pub fn load_audited_config(
    program_id: &Address,
    account: &AccountView,
) -> Result<AuditedConfig, ProgramError> {
    let config = load::<RingProgramConfig>(program_id, account)?;
    let mode = config.mode().ok_or(CustomRingError::InvalidRingMode)?;
    if config.has_legacy_auditor_key() {
        return Err(CustomRingError::LegacyAuditorKey.into());
    }
    Ok(AuditedConfig {
        auditor_pubkey: config.auditor_pubkey,
        has_policy: config.has_policy != 0,
        mode,
    })
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

/// The registry root at `index` a statement binds, `None` unless the ring escrows keys.
pub fn load_escrow_root(
    program_id: &Address,
    mode: RingMode,
    index: u8,
    accounts: &mut AccountIterator<'_>,
) -> Result<Option<[u8; 32]>, ProgramError> {
    match mode {
        RingMode::Off | RingMode::Anonymous if index != 0 => {
            Err(CustomRingError::UnexpectedMemberRegistryRoot.into())
        }
        RingMode::Off | RingMode::Anonymous => Ok(None),
        RingMode::Registry => {
            let account = accounts.next_account("member_registry_root")?;
            load::<MemberRegistryRoot>(program_id, account)?
                .root_at(index)
                .map(Some)
                .ok_or_else(|| CustomRingError::StaleMemberRegistryRoot.into())
        }
    }
}

/// The ring's registry root at history slot `index`.
pub fn load_registry_root(
    program_id: &Address,
    account: &AccountView,
    index: u8,
) -> Result<[u8; 32], ProgramError> {
    load::<MemberRegistryRoot>(program_id, account)?
        .root_at(index)
        .ok_or_else(|| CustomRingError::StaleMemberRegistryRoot.into())
}

/// A curator's registry root account, the `b"members"` PDA of its owning program.
pub fn load_curator_registry(account: &AccountView) -> Result<Address, ProgramError> {
    let invalid = CustomRingError::InvalidCuratorRegistry;
    let curator_program = account.owner();
    let data = account.try_borrow().map_err(|_| invalid)?;
    let root = MemberRegistryRoot::from_data(&data).ok_or(invalid)?;
    let address = Address::derive_address(
        &[MemberRegistryRoot::SEED],
        Some(root.bump),
        curator_program,
    );
    if !address_eq(account.address(), &address) {
        return Err(invalid.into());
    }
    Ok(*account.address())
}

/// The root at `index` of the curator registry the policy sources pin by address.
pub fn load_curator_root(
    account: &AccountView,
    curator: &Address,
    index: u8,
) -> Result<[u8; 32], ProgramError> {
    if !address_eq(account.address(), curator) {
        return Err(CustomRingError::InvalidCuratorRegistry.into());
    }
    let data = account
        .try_borrow()
        .map_err(|_| CustomRingError::InvalidCuratorRegistry)?;
    MemberRegistryRoot::from_data(&data)
        .ok_or(CustomRingError::InvalidCuratorRegistry)?
        .root_at(index)
        .ok_or_else(|| CustomRingError::StaleMemberRegistryRoot.into())
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
