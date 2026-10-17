use custom_ring_interface::{
    CustomRingError, PolicyConfig, PolicyTableIxData, RingProgramConfig, POLICY_CONFIG,
};
use pinocchio::{
    sysvars::{clock::Clock, Sysvar},
    AccountView, Address, ProgramResult,
};
use zolana_account_checks::AccountIterator;
use zolana_ring_policy::{ListNamespace, NAMESPACE_PDA_SEED};

use crate::{
    instructions::{
        loader::{check_upgrade_authority, load, load_spp_tree_id},
        policy_shared::{bind_table, compute_policy_hash},
        shared::{check_system_program, create_pda, parse},
    },
    state::Init,
};

/// Only the program upgrade authority pins a table.
#[inline(never)]
pub fn process_create_policy_ix(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    let ix: PolicyTableIxData = parse(data)?;

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

    check_system_program(system_program)?;
    let ring = load::<RingProgramConfig>(program_id, config)?;
    if ring.has_policy == 0 {
        return Err(CustomRingError::PolicyOnAuditOnlyRing.into());
    }
    ring.mode().ok_or(CustomRingError::InvalidRingMode)?;
    drop(ring);
    let address_tree_id = load_spp_tree_id(address_tree, CustomRingError::InvalidAddressTree)?;
    check_upgrade_authority(program_id, authority, program, program_data)?;
    let bump =
        create_pda::<PolicyConfig, 1>(program_id, payer, policy_config, &[PolicyConfig::SEED])?;

    let (namespace, namespace_bump) =
        Address::derive_program_address(&[NAMESPACE_PDA_SEED], program_id)
            .ok_or(CustomRingError::InvalidNamespacePda)?;
    let bound = bind_table(&ix, curators, &namespace, address_tree.address())?;
    // Boxed, a whole policy config exceeds the SBF stack frame.
    let mut written = bytemuck::zeroed_box::<PolicyConfig>();
    written.discriminator = POLICY_CONFIG;
    written.policy_hash = compute_policy_hash(&bound.rules, &bound.sources)?;
    written.address_tree = *address_tree.address();
    written.address_tree_id = address_tree_id.to_le_bytes();
    written.namespace_bump = namespace_bump;
    written.bump = bump;
    written.namespace_owner_hash = ListNamespace::new(namespace.as_array())
        .map_err(CustomRingError::from)?
        .owner_hash;
    written.sources = bound.sources;
    written.rules = bound.rules;
    written.generation = 1u32.to_le_bytes();
    written.generation_slot = Clock::get()?.slot.to_le_bytes();
    Init(&*written).init(policy_config)
}
