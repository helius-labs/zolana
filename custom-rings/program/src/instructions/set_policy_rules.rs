use bytemuck::from_bytes_mut;
use custom_ring_interface::{PolicyConfig, PolicyTableIxData};
use pinocchio::{AccountView, Address, ProgramResult};
use zolana_account_checks::AccountIterator;

use crate::{
    error::CustomRingError,
    instructions::{
        loader::{load_policy_config, UpgradeAuthorityCheck},
        policy_shared::{namespace_pda, repin, Repin, TableBinding},
    },
};

/// Takes effect at once, a proof over the old hash fails at verification.
#[inline(never)]
pub fn process_set_policy_rules_ix(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    let ix: PolicyTableIxData =
        wincode::deserialize_exact(data).map_err(|_| CustomRingError::InvalidInstructionData)?;

    let mut iter = AccountIterator::new(accounts);
    let authority = iter.next_signer("authority")?;
    let policy_config = iter.next_mut("policy_config")?;
    let program = iter.next_account("program")?;
    let program_data = iter.next_account("program_data")?;
    let curators = iter.remaining_unchecked()?;

    UpgradeAuthorityCheck {
        program_id,
        authority,
        program,
        program_data,
    }
    .verify()?;
    let entries_tree = load_policy_config(program_id, policy_config)?.entries_tree;

    let (own_namespace, _) = namespace_pda(program_id)?;
    let bound = TableBinding {
        table: &ix,
        curators,
        own_namespace: &own_namespace,
        entries_tree: &entries_tree,
    }
    .bind()?;

    let mut data = policy_config.try_borrow_mut()?;
    let live: &mut PolicyConfig = from_bytes_mut(&mut data);
    repin(live, Repin::Table(&bound))
}
