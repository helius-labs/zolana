use crate::{
    error::CustomRingError,
    instructions::{
        loader::{load_config, load_spp_tree_id, UpgradeAuthorityCheck},
        policy_shared::{compute_policy_hash, namespace_pda, TableBinding},
        shared::PdaCheck,
    },
    state::PolicyConfigInit,
};
use custom_ring_interface::{PolicyConfig, PolicyTableIxData};
use pinocchio::{
    cpi::{Seed, Signer},
    sysvars::{clock::Clock, Sysvar},
    AccountView, Address, ProgramResult,
};
use zolana_account_checks::AccountIterator;
use zolana_ring_policy::ListNamespace;

/// Only the program upgrade authority pins a table.
#[inline(never)]
pub fn process_create_policy_ix(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    let ix: PolicyTableIxData =
        wincode::deserialize_exact(data).map_err(|_| CustomRingError::InvalidInstructionData)?;

    let mut iter = AccountIterator::new(accounts);
    let payer = iter.next_signer_mut("payer")?;
    let authority = iter.next_signer("authority")?;
    let config = iter.next_account("config")?;
    let policy_config = iter.next_mut("policy_config")?;
    let address_tree = iter.next_account("address_tree")?;
    let system_program = iter.next_account("system_program")?;
    let program = iter.next_account("program")?;
    let program_data = iter.next_account("program_data")?;
    let curators = iter.remaining_unchecked()?;

    if !pinocchio_system::check_id(system_program.address()) {
        return Err(CustomRingError::InvalidSystemProgram.into());
    }
    if load_config(program_id, config)?.has_policy == 0 {
        return Err(CustomRingError::PolicyOnAuditOnlyRing.into());
    }
    let address_tree_id = load_spp_tree_id(address_tree, CustomRingError::InvalidAddressTree)?;
    UpgradeAuthorityCheck {
        program_id,
        authority,
        program,
        program_data,
    }
    .verify()?;

    let bump = PdaCheck {
        program_id,
        address: policy_config.address(),
        seeds: &[PolicyConfig::SEED],
        mismatch: CustomRingError::InvalidPolicyConfigPda,
    }
    .verify()?;
    if policy_config.data_len() != 0 {
        return Err(CustomRingError::PolicyConfigAlreadyInitialized.into());
    }

    let (own_namespace, namespace_bump) = namespace_pda(program_id)?;
    let namespace_owner_hash = ListNamespace::new(own_namespace.as_array())
        .map_err(|_| CustomRingError::HashingFailed)?
        .owner_hash;
    let bound = TableBinding {
        table: &ix,
        curators,
        own_namespace: &own_namespace,
        address_tree: address_tree.address(),
    }
    .bind()?;
    let policy_hash = compute_policy_hash(&bound.rules, &bound.sources)?;
    let generation_slot = Clock::get()?.slot;

    let bump_seed = [bump];
    let seeds = [
        Seed::from(PolicyConfig::SEED),
        Seed::from(bump_seed.as_ref()),
    ];
    pinocchio_system::create_account_with_minimum_balance_signed(
        policy_config,
        PolicyConfig::SIZE,
        program_id,
        payer,
        None,
        &[Signer::from(seeds.as_ref())],
    )?;

    PolicyConfigInit {
        policy_hash,
        address_tree: *address_tree.address(),
        address_tree_id,
        namespace_bump,
        bump,
        namespace_owner_hash,
        sources: &bound.sources,
        rules: &bound.rules,
        generation_slot,
    }
    .write(policy_config)
}
