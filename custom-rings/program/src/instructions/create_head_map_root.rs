use custom_ring_interface::HeadMapRoot;
use pinocchio::{
    cpi::{Seed, Signer},
    AccountView, Address, ProgramResult,
};
use zolana_account_checks::AccountIterator;

use crate::{
    error::CustomRingError,
    instructions::{loader::load_authorized_config, shared::PdaCheck},
    state::HeadMapRootInitParams,
};

/// Initializes the ring's head-map root to the canonical empty root.
#[inline(never)]
pub fn process_create_head_map_root_ix(
    program_id: &Address,
    accounts: &mut [AccountView],
    _data: &[u8],
) -> ProgramResult {
    let mut iter = AccountIterator::new(accounts);
    let payer = iter.next_signer_mut("payer")?;
    let authority = iter.next_signer("authority")?;
    let config_account = iter.next_account("config")?;
    let root_account = iter.next_mut("head_map_root")?;
    let system_program = iter.next_account("system_program")?;

    if !pinocchio_system::check_id(system_program.address()) {
        return Err(CustomRingError::InvalidSystemProgram.into());
    }
    // 1. Authenticate the ring authority before allocating shared member state.
    load_authorized_config(program_id, config_account, authority)?;

    // 2. Initialize only the canonical sentinel root without replacing a live map.
    let bump = PdaCheck {
        program_id,
        address: root_account.address(),
        seeds: &[HeadMapRoot::SEED],
        mismatch: CustomRingError::InvalidHeadMapRoot,
    }
    .verify()?;
    let bump_seed = [bump];
    let seeds = [
        Seed::from(HeadMapRoot::SEED),
        Seed::from(bump_seed.as_ref()),
    ];
    pinocchio_system::create_account_with_minimum_balance_signed(
        root_account,
        HeadMapRoot::SIZE,
        program_id,
        payer,
        None,
        &[Signer::from(seeds.as_ref())],
    )?;
    HeadMapRootInitParams { bump }.init(root_account)
}
