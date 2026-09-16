use pinocchio::{
    cpi::Seed,
    error::ProgramError,
    sysvars::{rent::Rent, Sysvar},
    AccountView, ProgramResult,
};
use zolana_account_checks::AccountIterator;
use zolana_interface::{
    error::ShieldedPoolError, state::discriminator::TREE_ACCOUNT_DISCRIMINATOR,
    NULLIFIER_FILTER_SEED,
};
use zolana_tree::{
    nullifier_filter::{NullifierFilter, DEFAULT_BIT_BYTES, DEFAULT_HASHES},
    NullifierFilterMode, TreeAccount,
};

use super::{
    create_tree::allocate::{create_account, fund_tree, grow_tree, is_unallocated},
    protocol_config::loader::load_and_validate_protocol_authority,
    shared::{tree_error, verify_pda},
};

pub fn enable(accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    if !data.is_empty() {
        return Err(ProgramError::InvalidInstructionData);
    }
    let mut iter = AccountIterator::new(accounts);
    let payer = iter.next_signer("payer")?;
    let authority = iter.next_signer("authority")?;
    let config = iter.next_account("protocol_config")?;
    let tree = iter.next_mut("tree")?;
    let filter = iter.next_mut("nullifier_filter")?;
    let system = iter.next_account("system_program")?;
    if !pinocchio_system::check_id(system.address()) {
        return Err(ProgramError::IncorrectProgramId);
    }
    load_and_validate_protocol_authority(config, authority)?;
    let address = tree.address().to_bytes();
    let bump = verify_pda(
        filter.address(),
        &[NULLIFIER_FILTER_SEED, &address],
        &crate::ID,
    )?;
    let mut tree = TreeAccount::from_account_view_mut_allow_paused(
        tree,
        &crate::ID,
        TREE_ACCOUNT_DISCRIMINATOR,
    )
    .map_err(tree_error)?;
    if tree.nullifier_filter_mode() != NullifierFilterMode::Off
        || !tree.uses_compact_nullifiers()
        || tree.nullifier_tree().next_index != 1
        || tree.nullifier_tree().queue_next_index != 1
    {
        return Err(ShieldedPoolError::InvalidNullifierFilter.into());
    }
    let size = NullifierFilter::account_size(DEFAULT_BIT_BYTES)
        .ok_or(ShieldedPoolError::InvalidNullifierFilter)?;
    let lamports = Rent::get()?.try_minimum_balance(size)?;
    if is_unallocated(filter) {
        let bump = [bump];
        let seeds = [
            Seed::from(NULLIFIER_FILTER_SEED),
            Seed::from(&address),
            Seed::from(&bump),
        ];
        create_account(payer, filter, &seeds, size, lamports)?;
    } else {
        grow_tree(filter, size)?;
    }
    if filter.data_len() != size {
        return Ok(());
    }
    fund_tree(payer, filter, lamports)?;
    NullifierFilter::init_zeroed(&mut filter.try_borrow_mut()?, &address, DEFAULT_HASHES)
        .map_err(|_| ShieldedPoolError::InvalidNullifierFilter)?;
    tree.enable_nullifier_filter().map_err(tree_error)
}

pub fn retire(accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    if !data.is_empty() {
        return Err(ProgramError::InvalidInstructionData);
    }
    let mut iter = AccountIterator::new(accounts);
    let authority = iter.next_signer("authority")?;
    let config = iter.next_account("protocol_config")?;
    let tree = iter.next_mut("tree")?;
    load_and_validate_protocol_authority(config, authority)?;
    TreeAccount::from_account_view_mut_allow_paused(tree, &crate::ID, TREE_ACCOUNT_DISCRIMINATOR)
        .map_err(tree_error)?
        .retire_nullifier_filter()
        .map_err(tree_error)
}
