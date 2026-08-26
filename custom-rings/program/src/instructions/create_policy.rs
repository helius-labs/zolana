use crate::{
    error::CustomRingError,
    instructions::{
        loader::UpgradeAuthorityCheck,
        policy_shared::{kind_owners, load_curator_policy_config, records_pda},
        shared::PdaCheck,
    },
    state::PolicyConfigInitParams,
};
use bytemuck::Zeroable;
use custom_ring_interface::{
    CreatePolicyIxData, PolicyConfig, PolicySourceSlot, PolicySourceSpec, N_POLICY_SOURCE_SLOTS,
    POLICY,
};
use pinocchio::{
    cpi::{Seed, Signer},
    error::ProgramError,
    AccountView, Address, ProgramResult,
};
use zolana_account_checks::AccountIterator;
use zolana_interface::{
    state::discriminator::TREE_ACCOUNT_DISCRIMINATOR, SHIELDED_POOL_PROGRAM_ID,
};
use zolana_ring_policy::{RecordKind, RuleSource};

/// The table is part of the deployed program, only its upgrade authority can
/// pin the hash.
#[inline(never)]
pub fn process_create_policy_ix(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    let ix: CreatePolicyIxData =
        wincode::deserialize_exact(data).map_err(|_| CustomRingError::InvalidInstructionData)?;

    let mut iter = AccountIterator::new(accounts);
    let payer = iter.next_signer_mut("payer")?;
    let authority = iter.next_signer("authority")?;
    let policy_config = iter.next_mut("policy_config")?;
    let records_tree = iter.next_account("records_tree")?;
    let system_program = iter.next_account("system_program")?;
    let program = iter.next_account("program")?;
    let program_data = iter.next_account("program_data")?;
    let curators = iter.remaining_unchecked()?;

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

    let (own_records, records_bump) = records_pda(program_id)?;
    let sources = resolve_sources(&ix.sources, curators, &own_records, records_tree.address())?;
    let policy_hash = POLICY
        .hash(&kind_owners(&sources)?)
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
        sources,
    }
    .init(policy_config)
}

/// The stored map is a bijection with the kinds the compiled table references,
/// a curator entry copies the curator's resolved owner for the kind.
pub(crate) fn resolve_sources(
    specs: &[PolicySourceSpec],
    curators: &[AccountView],
    own_records: &Address,
    records_tree: &Address,
) -> Result<[PolicySourceSlot; N_POLICY_SOURCE_SLOTS], ProgramError> {
    let mut referenced = [false; N_POLICY_SOURCE_SLOTS];
    for rule in POLICY.rules() {
        if let RuleSource::Records(kind) = rule.source {
            referenced[kind as usize - 1] = true;
        }
    }
    let mut sources = [PolicySourceSlot::zeroed(); N_POLICY_SOURCE_SLOTS];
    let mut seen = [false; N_POLICY_SOURCE_SLOTS];
    for spec in specs {
        let kind =
            RecordKind::try_from(spec.kind).map_err(|_| CustomRingError::InvalidPolicySource)?;
        let index = kind as usize - 1;
        if !referenced[index] || seen[index] {
            return Err(CustomRingError::InvalidPolicySource.into());
        }
        seen[index] = true;
        let records = match spec.source {
            0 => *own_records,
            n => {
                let curator = curators
                    .get(usize::from(n) - 1)
                    .ok_or(CustomRingError::InvalidPolicySource)?;
                // Copies the curator's resolved owner, a curator of a curator
                // never chains on chain.
                load_curator_policy_config(curator, records_tree)?
                    .source_for(kind as u8)
                    .ok_or(CustomRingError::CuratorSourceMissing)?
            }
        };
        sources[index] = PolicySourceSlot {
            kind: kind as u8,
            records,
        };
    }
    if seen != referenced {
        return Err(CustomRingError::InvalidPolicySource.into());
    }
    Ok(sources)
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
