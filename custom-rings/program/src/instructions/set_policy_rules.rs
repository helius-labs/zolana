use custom_ring_interface::{CustomRingError, PolicyConfig, PolicyTableIxData};
use pinocchio::{AccountView, Address, ProgramResult};
use zolana_account_checks::AccountIterator;

use crate::instructions::{
    loader::{check_upgrade_authority, load_mut},
    policy_shared::{bind_table, repin},
    shared::{namespace_address, parse},
};

/// Takes effect at once, a proof over the old hash fails at verification.
#[inline(never)]
pub fn process_set_policy_rules_ix(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    let ix: PolicyTableIxData = parse(data)?;

    let mut iter = AccountIterator::new(accounts);
    let authority = iter.next_signer("authority")?;
    let policy_config = iter.next_mut("policy_config")?;
    let program = iter.next_account("program")?;
    let program_data = iter.next_account("program_data")?;
    let curators = iter.remaining_unchecked()?;

    check_upgrade_authority(program_id, authority, program, program_data)?;
    let mut live = load_mut::<PolicyConfig>(program_id, policy_config)?;
    let namespace = namespace_address(program_id, live.namespace_bump);
    let bound = bind_table(&ix, curators, &namespace, &live.address_tree)?;
    let window_slots = live.rules.window_slots();
    if window_slots != 0 && bound.rules.window_slots() != window_slots {
        return Err(CustomRingError::VelocityWindowImmutable.into());
    }
    live.rules = bound.rules;
    repin(&mut live, &bound.sources)
}
