//! Per-verifying-key registry accounts for this program, mirroring the
//! shielded pool's `instructions/vk_registry.rs`: permissionless step-machine
//! creation, address-commitment authentication, prepared-operand verify.

use pinocchio::{
    address::{address_eq, Address},
    cpi::{Seed, Signer},
    error::ProgramError,
    sysvars::{rent::Rent, Sysvar},
    AccountView, ProgramResult, Resize,
};
use pinocchio_system::instructions::Transfer;
use zolana_account_checks::AccountIterator;
use zolana_interface::{
    state::vk_registry::VkRegistryHeader,
    verifying_keys::registry_spec::{
        vk_registry_account_len, vk_registry_blob_offset, vk_registry_gt_offset,
        vk_registry_source_offset, VkRegistrySpec, VK_REGISTRY_BLOB_BYTES, VK_REGISTRY_GT_BYTES,
        VK_REGISTRY_PDA_SEED,
    },
};

use crate::{error::TimelockEscrowError, vk_registry_specs::VK_REGISTRY_SPECS};

/// VKs in `VK_REGISTRY_SPECS` order.
static VK_CATALOG: [&groth16_solana::groth16::Groth16Verifyingkey<'static>; 2] = [
    &crate::verifying_keys::escrow::VERIFYINGKEY,
    &crate::verifying_keys::withdraw::VERIFYINGKEY,
];

const MAX_PERMITTED_DATA_INCREASE: usize = 10_240;

pub fn process_init_vk_registry_ix(accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    let [vk_index] = data else {
        return Err(TimelockEscrowError::InvalidInstructionData.into());
    };
    let vk_index = *vk_index as usize;
    let vk = *VK_CATALOG
        .get(vk_index)
        .ok_or(TimelockEscrowError::InvalidVkRegistryIndex)?;
    let spec = &VK_REGISTRY_SPECS[vk_index];

    let mut iter = AccountIterator::new(accounts);
    let payer = iter.next_signer_mut("payer")?;
    let registry = iter.next_mut("vk_registry")?;
    let system_program = iter.next_account("system_program")?;
    if !pinocchio_system::check_id(system_program.address()) {
        return Err(ProgramError::IncorrectProgramId);
    }
    if !address_eq(registry.address(), &Address::from(spec.address)) {
        return Err(TimelockEscrowError::InvalidVkRegistryAccount.into());
    }

    let target_len = vk_registry_account_len(spec.g2_count as usize);
    if registry.data_len() == 0 {
        let bump_seed = [spec.bump];
        let seeds = [
            Seed::from(VK_REGISTRY_PDA_SEED),
            Seed::from(spec.digest.as_ref()),
            Seed::from(bump_seed.as_ref()),
        ];
        pinocchio_system::create_account_with_minimum_balance_signed(
            registry,
            target_len.min(MAX_PERMITTED_DATA_INCREASE),
            &crate::ID,
            payer,
            None,
            &[Signer::from(seeds.as_ref())],
        )?;
        let mut account_data = registry.try_borrow_mut()?;
        let header: &mut VkRegistryHeader =
            bytemuck::from_bytes_mut(&mut account_data[..VkRegistryHeader::SIZE]);
        header
            .init(spec.g2_count, spec.bump)
            .map_err(|_| TimelockEscrowError::VkRegistryAlreadyInitialized)?;
        return Ok(());
    }

    check_unfinalized(registry, spec)?;
    if registry.data_len() < target_len {
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
        return registry.resize(new_len);
    }

    let mut sources = [[0u8; 128]; 5];
    sources[0] = vk.vk_beta_g2;
    sources[1] = vk.vk_gamma_g2;
    sources[2] = vk.vk_delta_g2;
    if let Some(commitment) = vk.vk_commitment {
        if spec.g2_count != 5 {
            return Err(TimelockEscrowError::InvalidVkRegistryAccount.into());
        }
        sources[3] = commitment.g2;
        sources[4] = commitment.g_sigma_neg_g2;
    } else if spec.g2_count != 3 {
        return Err(TimelockEscrowError::InvalidVkRegistryAccount.into());
    }

    let mut account_data = registry.try_borrow_mut()?;
    for (index, source) in sources.iter().take(spec.g2_count as usize).enumerate() {
        let source_offset = vk_registry_source_offset(index);
        account_data[source_offset..source_offset + 128].copy_from_slice(source);
        let blob_offset = vk_registry_blob_offset(index);
        groth16_solana::vk_registry::g2_prepare(
            source,
            &mut account_data[blob_offset..blob_offset + VK_REGISTRY_BLOB_BYTES],
        )
        .map_err(|_| TimelockEscrowError::VkRegistryInitFailed)?;
    }
    let target =
        groth16_solana::vk_registry::pairing_map(&[groth16_solana::vk_registry::G1G2Pair {
            g1: vk.vk_alpha_g1,
            g2: vk.vk_beta_g2,
        }])
        .map_err(|_| TimelockEscrowError::VkRegistryInitFailed)?;
    let gt_offset = vk_registry_gt_offset(spec.g2_count as usize);
    account_data[gt_offset..gt_offset + VK_REGISTRY_GT_BYTES].copy_from_slice(&target);

    let header: &mut VkRegistryHeader =
        bytemuck::from_bytes_mut(&mut account_data[..VkRegistryHeader::SIZE]);
    header.finalized = 1;
    Ok(())
}

fn check_unfinalized(registry: &AccountView, spec: &VkRegistrySpec) -> ProgramResult {
    if !registry.owned_by(&crate::ID) {
        return Err(TimelockEscrowError::InvalidVkRegistryAccount.into());
    }
    let data = registry.try_borrow()?;
    let header: &VkRegistryHeader = bytemuck::from_bytes(&data[..VkRegistryHeader::SIZE]);
    header
        .check(spec.g2_count)
        .map_err(|_| TimelockEscrowError::InvalidVkRegistryAccount)?;
    if header.is_finalized() {
        return Err(TimelockEscrowError::VkRegistryAlreadyInitialized.into());
    }
    Ok(())
}

/// Split the registry account for `spec` off the front of the remaining
/// account list when the caller supplied it. Address detection is sound
/// because the address is a PDA commitment to this VK's key material.
pub fn split_vk_registry<'a>(
    accounts: &'a [AccountView],
    spec: &VkRegistrySpec,
) -> (Option<&'a AccountView>, &'a [AccountView]) {
    match accounts.split_first() {
        Some((first, rest)) if address_eq(first.address(), &Address::from(spec.address)) => {
            (Some(first), rest)
        }
        _ => (None, accounts),
    }
}

/// Borrow finalized registry data. The address compare in
/// [`split_vk_registry`] is the trust decision; owner and header checks are
/// defense in depth.
pub fn load_finalized_vk_registry<'a>(
    registry: &'a AccountView,
    spec: &VkRegistrySpec,
) -> Result<pinocchio::account::Ref<'a, [u8]>, ProgramError> {
    if !registry.owned_by(&crate::ID) {
        return Err(TimelockEscrowError::InvalidVkRegistryAccount.into());
    }
    let data = registry.try_borrow()?;
    {
        let header: &VkRegistryHeader = bytemuck::from_bytes(
            data.get(..VkRegistryHeader::SIZE)
                .ok_or(TimelockEscrowError::InvalidVkRegistryAccount)?,
        );
        header
            .check(spec.g2_count)
            .map_err(|_| TimelockEscrowError::InvalidVkRegistryAccount)?;
        if !header.is_finalized() {
            return Err(TimelockEscrowError::VkRegistryNotReady.into());
        }
    }
    if data.len() != vk_registry_account_len(spec.g2_count as usize) {
        return Err(TimelockEscrowError::InvalidVkRegistryAccount.into());
    }
    Ok(data)
}

/// Prepared refs over finalized registry data, in the canonical source order
/// the spec's digest committed to.
pub fn prepared_vk_refs<'a>(
    data: &'a [u8],
    spec: &VkRegistrySpec,
) -> Result<groth16_solana::groth16::PreparedVkRefs<'a>, ProgramError> {
    let g2_count = spec.g2_count as usize;
    if data.len() != vk_registry_account_len(g2_count) {
        return Err(TimelockEscrowError::InvalidVkRegistryAccount.into());
    }
    let blob = |index: usize| {
        let offset = vk_registry_blob_offset(index);
        &data[offset..offset + VK_REGISTRY_BLOB_BYTES]
    };
    let gt_offset = vk_registry_gt_offset(g2_count);
    let gt_target: &[u8; VK_REGISTRY_GT_BYTES] = data[gt_offset..gt_offset + VK_REGISTRY_GT_BYTES]
        .try_into()
        .map_err(|_| TimelockEscrowError::InvalidVkRegistryAccount)?;
    Ok(groth16_solana::groth16::PreparedVkRefs {
        beta: blob(0),
        gamma: blob(1),
        delta: blob(2),
        commitment: (g2_count == 5).then(|| (blob(3), blob(4))),
        gt_target: Some(gt_target),
    })
}
