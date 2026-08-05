//! Permissionless one-time creation of a per-verifying-key registry account.
//!
//! The account exceeds the per-transaction allocation cap, so creation is a
//! step machine driven by resending one instruction. The steps are to create
//! the PDA at the cap, grow it once per transaction, then in the final step
//! run the prepare syscalls over the compile-time VK constants and freeze.
//! Contents are trustworthy without an authority. They derive only from
//! const sources and deterministic syscalls, the account is writable only by
//! this program, and no write path exists after `finalized` is set.

use pinocchio::{
    address::{address_eq, Address},
    error::ProgramError,
    sysvars::{rent::Rent, Sysvar},
    AccountView, ProgramResult, Resize,
};
use pinocchio_system::instructions::Transfer;
use zolana_account_checks::AccountIterator;
use zolana_interface::{
    error::ShieldedPoolError,
    state::vk_registry::VkRegistryHeader,
    verifying_keys::{
        catalog::vk_catalog_entry,
        registry_spec::{
            vk_registry_account_len, vk_registry_blob_offset, vk_registry_gt_offset,
            vk_registry_source_offset, VkRegistrySpec, VK_REGISTRY_BLOB_BYTES,
            VK_REGISTRY_GT_BYTES, VK_REGISTRY_PDA_SEED,
        },
    },
};

use crate::instructions::shared::CreatePdaAccount;

const MAX_PERMITTED_DATA_INCREASE: usize = 10_240;

pub fn process_init_vk_registry(accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    let [vk_index] = data else {
        return Err(ShieldedPoolError::InvalidInstructionData.into());
    };
    // One accessor resolves the key and the spec, so the account address can
    // never commit to a different key than the one prepared into it.
    let (_, vk, spec) =
        vk_catalog_entry(*vk_index as usize).ok_or(ShieldedPoolError::InvalidVkRegistryIndex)?;

    let mut iter = AccountIterator::new(accounts);
    let payer = iter.next_signer_mut("payer")?;
    let registry = iter.next_mut("vk_registry")?;
    let system_program = iter.next_account("system_program")?;
    if !pinocchio_system::check_id(system_program.address()) {
        return Err(ProgramError::IncorrectProgramId);
    }

    // The address is the access control. The PDA seeds commit to the keyset
    // digest, so only the account for exactly this VK can pass.
    if !address_eq(registry.address(), &Address::from(spec.address)) {
        return Err(ShieldedPoolError::InvalidVkRegistryAccount.into());
    }

    let target_len = vk_registry_account_len(spec.g2_count as usize);
    if registry.data_len() == 0 {
        return create_registry(payer, registry, spec, target_len);
    }
    if registry.data_len() < target_len {
        return grow_registry(payer, registry, spec, target_len);
    }
    finalize_registry(registry, spec, vk, target_len)
}

fn create_registry(
    payer: &AccountView,
    registry: &mut AccountView,
    spec: &VkRegistrySpec,
    target_len: usize,
) -> ProgramResult {
    CreatePdaAccount {
        fee_payer: payer,
        new_account: registry,
        space: target_len.min(MAX_PERMITTED_DATA_INCREASE),
        owner: &crate::ID,
        signer_seeds: [VK_REGISTRY_PDA_SEED, &spec.digest],
        bump: spec.bump,
    }
    .execute()?;
    let mut data = registry.try_borrow_mut()?;
    let header = header_mut(&mut data)?;
    header
        .init(spec.g2_count, spec.bump)
        .map_err(|_| ShieldedPoolError::VkRegistryAlreadyInitialized)?;
    Ok(())
}

fn grow_registry(
    payer: &AccountView,
    registry: &mut AccountView,
    spec: &VkRegistrySpec,
    target_len: usize,
) -> ProgramResult {
    check_header(registry, spec)?;
    let new_len = registry
        .data_len()
        .saturating_add(MAX_PERMITTED_DATA_INCREASE)
        .min(target_len);
    let rent_minimum = Rent::get()?.try_minimum_balance(new_len)?;
    let top_up = rent_minimum.saturating_sub(registry.lamports());
    if top_up > 0 {
        Transfer {
            from: payer,
            to: registry,
            lamports: top_up,
        }
        .invoke()?;
    }
    registry.resize(new_len)
}

fn finalize_registry(
    registry: &mut AccountView,
    spec: &VkRegistrySpec,
    vk: &groth16_solana::groth16::Groth16Verifyingkey<'static>,
    target_len: usize,
) -> ProgramResult {
    check_header(registry, spec)?;
    if registry.data_len() != target_len {
        return Err(ShieldedPoolError::InvalidVkRegistryAccount.into());
    }

    let mut sources = [[0u8; 128]; 5];
    sources[0] = vk.vk_beta_g2;
    sources[1] = vk.vk_gamma_g2;
    sources[2] = vk.vk_delta_g2;
    if let Some(commitment) = vk.vk_commitment {
        if spec.g2_count != 5 {
            return Err(ShieldedPoolError::InvalidVkRegistryAccount.into());
        }
        sources[3] = commitment.g2;
        sources[4] = commitment.g_sigma_neg_g2;
    } else if spec.g2_count != 3 {
        return Err(ShieldedPoolError::InvalidVkRegistryAccount.into());
    }

    let mut data = registry.try_borrow_mut()?;
    for (index, source) in sources.iter().take(spec.g2_count as usize).enumerate() {
        let source_offset = vk_registry_source_offset(index);
        data.get_mut(source_offset..source_offset + 128)
            .ok_or(ShieldedPoolError::InvalidVkRegistryAccount)?
            .copy_from_slice(source);
        let blob_offset = vk_registry_blob_offset(index);
        groth16_solana::vk_registry::g2_prepare(
            source,
            data.get_mut(blob_offset..blob_offset + VK_REGISTRY_BLOB_BYTES)
                .ok_or(ShieldedPoolError::InvalidVkRegistryAccount)?,
        )
        .map_err(|_| ShieldedPoolError::VkRegistryInitFailed)?;
    }

    let target =
        groth16_solana::vk_registry::pairing_map(&[groth16_solana::vk_registry::G1G2Pair {
            g1: vk.vk_alpha_g1,
            g2: vk.vk_beta_g2,
        }])
        .map_err(|_| ShieldedPoolError::VkRegistryInitFailed)?;
    let gt_offset = vk_registry_gt_offset(spec.g2_count as usize);
    data.get_mut(gt_offset..gt_offset + VK_REGISTRY_GT_BYTES)
        .ok_or(ShieldedPoolError::InvalidVkRegistryAccount)?
        .copy_from_slice(&target);

    header_mut(&mut data)?.finalized = 1;
    Ok(())
}

fn header(data: &[u8]) -> Result<&VkRegistryHeader, ProgramError> {
    bytemuck::try_from_bytes(
        data.get(..VkRegistryHeader::SIZE)
            .ok_or(ShieldedPoolError::InvalidVkRegistryAccount)?,
    )
    .map_err(|_| ShieldedPoolError::InvalidVkRegistryAccount.into())
}

fn header_mut(data: &mut [u8]) -> Result<&mut VkRegistryHeader, ProgramError> {
    bytemuck::try_from_bytes_mut(
        data.get_mut(..VkRegistryHeader::SIZE)
            .ok_or(ShieldedPoolError::InvalidVkRegistryAccount)?,
    )
    .map_err(|_| ShieldedPoolError::InvalidVkRegistryAccount.into())
}

/// Borrow a finalized registry's data for the verified path. The address
/// compare against the codegen'd spec is the entire trust decision. Only
/// this program can sign the PDA's creation, so an address match implies
/// init-produced contents. Owner and header checks are defense in depth.
pub fn load_finalized_vk_registry<'a>(
    registry: &'a AccountView,
    spec: &VkRegistrySpec,
) -> Result<pinocchio::account::Ref<'a, [u8]>, ProgramError> {
    if !address_eq(registry.address(), &Address::from(spec.address)) {
        return Err(ShieldedPoolError::InvalidVkRegistryAccount.into());
    }
    if !registry.owned_by(&crate::ID) {
        return Err(ShieldedPoolError::InvalidVkRegistryAccount.into());
    }
    let data = registry.try_borrow()?;
    {
        let header = header(&data)?;
        header
            .check(spec.g2_count)
            .map_err(|_| ShieldedPoolError::InvalidVkRegistryAccount)?;
        if !header.is_finalized() {
            return Err(ShieldedPoolError::VkRegistryNotReady.into());
        }
    }
    if data.len() != vk_registry_account_len(spec.g2_count as usize) {
        return Err(ShieldedPoolError::InvalidVkRegistryAccount.into());
    }
    Ok(data)
}

/// Borrowed prepared refs over finalized registry data, in the canonical
/// source order the spec's digest committed to.
pub fn prepared_vk_refs<'a>(
    data: &'a [u8],
    spec: &VkRegistrySpec,
) -> Result<groth16_solana::groth16::PreparedVkRefs<'a>, ProgramError> {
    let g2_count = spec.g2_count as usize;
    if data.len() != vk_registry_account_len(g2_count) {
        return Err(ShieldedPoolError::InvalidVkRegistryAccount.into());
    }
    let blob = |index: usize| -> Result<&'a [u8], ProgramError> {
        let offset = vk_registry_blob_offset(index);
        data.get(offset..offset + VK_REGISTRY_BLOB_BYTES)
            .ok_or_else(|| ShieldedPoolError::InvalidVkRegistryAccount.into())
    };
    let gt_offset = vk_registry_gt_offset(g2_count);
    let gt_target: &[u8; VK_REGISTRY_GT_BYTES] = data
        .get(gt_offset..gt_offset + VK_REGISTRY_GT_BYTES)
        .ok_or(ShieldedPoolError::InvalidVkRegistryAccount)?
        .try_into()
        .map_err(|_| ShieldedPoolError::InvalidVkRegistryAccount)?;
    let commitment = match g2_count {
        5 => Some((blob(3)?, blob(4)?)),
        _ => None,
    };
    Ok(groth16_solana::groth16::PreparedVkRefs {
        beta: blob(0)?,
        gamma: blob(1)?,
        delta: blob(2)?,
        commitment,
        gt_target: Some(gt_target),
    })
}

fn check_header(registry: &AccountView, spec: &VkRegistrySpec) -> ProgramResult {
    if !registry.owned_by(&crate::ID) {
        return Err(ShieldedPoolError::InvalidVkRegistryAccount.into());
    }
    let data = registry.try_borrow()?;
    let header = header(&data)?;
    header
        .check(spec.g2_count)
        .map_err(|_| ShieldedPoolError::InvalidVkRegistryAccount)?;
    if header.is_finalized() {
        return Err(ShieldedPoolError::VkRegistryAlreadyInitialized.into());
    }
    Ok(())
}
