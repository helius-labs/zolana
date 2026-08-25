use custom_ring_interface::PolicyConfig;
use pinocchio::{
    cpi::{Seed, Signer},
    error::ProgramError,
    AccountView, Address, ProgramResult,
};
use zolana_account_checks::AccountIterator;
use zolana_ring_policy::RecordsOwner;
#[cfg(any(target_os = "solana", target_arch = "bpf"))]
use zolana_ring_policy::POLICY_RECORDS_PDA_SEED;

use crate::{
    error::CustomRingError,
    instructions::{loader::UpgradeAuthorityCheck, shared::PdaCheck},
    policy::POLICY,
    state::PolicyConfigInitParams,
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
    let system_program = iter.next_account("system_program")?;
    let program = iter.next_account("program")?;
    let program_data = iter.next_account("program_data")?;

    if !pinocchio_system::check_id(system_program.address()) {
        return Err(CustomRingError::InvalidSystemProgram.into());
    }
    UpgradeAuthorityCheck {
        program_id,
        authority,
        program,
        program_data,
    }
    .verify()?;
    if POLICY.is_empty() {
        return Err(CustomRingError::EmptyPolicy.into());
    }

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

    let (records_address, records_bump) = derive_records_pda(program_id)?;
    let owner = RecordsOwner::new(records_address.as_array())
        .map_err(|_| CustomRingError::HashingFailed)?;
    let policy_hash = POLICY
        .hash(&owner.owner_hash)
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
        records_bump,
        bump,
    }
    .init(policy_config)
}

#[cfg(any(target_os = "solana", target_arch = "bpf"))]
fn derive_records_pda(program_id: &Address) -> Result<(Address, u8), ProgramError> {
    Ok(Address::find_program_address(
        &[POLICY_RECORDS_PDA_SEED],
        program_id,
    ))
}

#[cfg(not(any(target_os = "solana", target_arch = "bpf")))]
fn derive_records_pda(_program_id: &Address) -> Result<(Address, u8), ProgramError> {
    Err(CustomRingError::InvalidRecordsPda.into())
}
