use crate::{
    error::CustomRingError,
    instructions::{
        loader::UpgradeAuthorityCheck,
        policy_shared::{records_owner, records_pda},
        shared::PdaCheck,
    },
    state::PolicyConfigInitParams,
};
use custom_ring_interface::{PolicyConfig, POLICY};
use pinocchio::{
    cpi::{Seed, Signer},
    AccountView, Address, ProgramResult,
};
use zolana_account_checks::AccountIterator;
use zolana_interface::{
    state::discriminator::TREE_ACCOUNT_DISCRIMINATOR, SHIELDED_POOL_PROGRAM_ID,
};

/// The table is part of the deployed program, only its upgrade authority can
/// pin the hash.
#[inline(never)]
pub fn process_create_policy_ix(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    if !data.is_empty() {
        return Err(CustomRingError::InvalidInstructionData.into());
    }

    let mut iter = AccountIterator::new(accounts);
    let payer = iter.next_signer_mut("payer")?;
    let authority = iter.next_signer("authority")?;
    let policy_config = iter.next_mut("policy_config")?;
    let records_tree = iter.next_account("records_tree")?;
    let system_program = iter.next_account("system_program")?;
    let program = iter.next_account("program")?;
    let program_data = iter.next_account("program_data")?;

    if !pinocchio_system::check_id(system_program.address()) {
        return Err(CustomRingError::InvalidSystemProgram.into());
    }
    check_records_tree(records_tree)?;
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

    let (_, records_bump) = records_pda(program_id)?;
    let policy_hash = POLICY
        .hash(&records_owner(program_id)?.owner_hash)
        .map_err(|_| CustomRingError::HashingFailed)?;

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
        records_tree: *records_tree.address(),
        records_bump,
        bump,
    }
    .init(policy_config)
}

fn check_records_tree(account: &AccountView) -> ProgramResult {
    if account.owner().as_array() != &SHIELDED_POOL_PROGRAM_ID {
        return Err(CustomRingError::InvalidRecordsTree.into());
    }
    let data = account
        .try_borrow()
        .map_err(|_| CustomRingError::InvalidRecordsTree)?;
    if data.first() != Some(&TREE_ACCOUNT_DISCRIMINATOR) {
        return Err(CustomRingError::InvalidRecordsTree.into());
    }
    Ok(())
}
