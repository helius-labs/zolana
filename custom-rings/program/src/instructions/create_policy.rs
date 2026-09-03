use crate::{
    error::CustomRingError,
    instructions::{
        loader::UpgradeAuthorityCheck,
        policy_shared::{compute_policy_hash, namespace_pda, BoundTable, TableBinding},
        shared::PdaCheck,
    },
    state::PolicyConfigInitParams,
};
use custom_ring_interface::{PolicyConfig, PolicyTableIxData};
use pinocchio::{
    cpi::{Seed, Signer},
    sysvars::{clock::Clock, Sysvar},
    AccountView, Address, ProgramResult,
};
use zolana_account_checks::AccountIterator;
use zolana_interface::{
    state::discriminator::TREE_ACCOUNT_DISCRIMINATOR, SHIELDED_POOL_PROGRAM_ID,
};

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
    let policy_config = iter.next_mut("policy_config")?;
    let entries_tree = iter.next_account("entries_tree")?;
    let system_program = iter.next_account("system_program")?;
    let program = iter.next_account("program")?;
    let program_data = iter.next_account("program_data")?;
    let curators = iter.remaining_unchecked()?;

    if !pinocchio_system::check_id(system_program.address()) {
        return Err(CustomRingError::InvalidSystemProgram.into());
    }
    check_entries_tree(entries_tree)?;
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
    let BoundTable { rules, sources } = TableBinding {
        table: &ix,
        curators,
        own_namespace: &own_namespace,
        entries_tree: entries_tree.address(),
    }
    .bind()?;
    let policy_hash = compute_policy_hash(&rules, &sources)?;
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

    PolicyConfigInitParams {
        policy_hash,
        entries_tree: *entries_tree.address(),
        namespace_bump,
        bump,
        sources,
        rules,
        generation_slot,
    }
    .init(policy_config)
}

fn check_entries_tree(account: &AccountView) -> ProgramResult {
    if account.owner().as_array() != &SHIELDED_POOL_PROGRAM_ID {
        return Err(CustomRingError::InvalidEntriesTree.into());
    }
    let data = account
        .try_borrow()
        .map_err(|_| CustomRingError::InvalidEntriesTree)?;
    if data.first() != Some(&TREE_ACCOUNT_DISCRIMINATOR) {
        return Err(CustomRingError::InvalidEntriesTree.into());
    }
    Ok(())
}
