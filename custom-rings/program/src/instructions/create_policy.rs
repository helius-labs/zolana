use crate::{
    error::CustomRingError,
    instructions::{
        loader::UpgradeAuthorityCheck,
        policy_shared::{compute_policy_hash, load_curator_policy_config, namespace_pda},
        shared::PdaCheck,
    },
    state::PolicyConfigInitParams,
};
use bytemuck::Zeroable;
use custom_ring_interface::{
    CreatePolicyIxData, PolicyConfig, SourceSlot, SourceSpec, N_SOURCE_SLOTS, RULES,
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
use zolana_ring_policy::ListId;

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
    let sources = resolve_sources(
        &ix.sources,
        curators,
        &own_namespace,
        entries_tree.address(),
    )?;
    let policy_hash = compute_policy_hash(&sources)?;

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
    }
    .init(policy_config)
}

/// The stored map is a bijection with the lists the compiled table references.
pub(crate) fn resolve_sources(
    specs: &[SourceSpec],
    curators: &[AccountView],
    own_namespace: &Address,
    entries_tree: &Address,
) -> Result<[SourceSlot; N_SOURCE_SLOTS], ProgramError> {
    let mut referenced = [false; N_SOURCE_SLOTS];
    for rule in RULES.rules() {
        for list_id in rule.referenced_lists() {
            referenced[list_id as usize - 1] = true;
        }
    }
    let mut sources = [SourceSlot::zeroed(); N_SOURCE_SLOTS];
    let mut seen = [false; N_SOURCE_SLOTS];
    for spec in specs {
        let list_id = ListId::try_from(spec.list_id).map_err(|_| CustomRingError::InvalidSource)?;
        let index = list_id as usize - 1;
        if !referenced[index] || seen[index] {
            return Err(CustomRingError::InvalidSource.into());
        }
        seen[index] = true;
        let entries = match spec.source {
            0 => *own_namespace,
            n => {
                let curator = curators
                    .get(usize::from(n) - 1)
                    .ok_or(CustomRingError::InvalidSource)?;
                // Copies the curator's resolved owner, a curator of a curator
                // never chains.
                load_curator_policy_config(curator, entries_tree)?
                    .source_for(list_id as u8)
                    .ok_or(CustomRingError::CuratorSourceMissing)?
            }
        };
        sources[index] = SourceSlot {
            list_id: list_id as u8,
            namespace: entries,
        };
    }
    if seen != referenced {
        return Err(CustomRingError::InvalidSource.into());
    }
    Ok(sources)
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
