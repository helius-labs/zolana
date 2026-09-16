use pinocchio::{
    cpi::Seed,
    error::ProgramError,
    sysvars::{rent::Rent, Sysvar},
    AccountView, ProgramResult,
};
use zolana_account_checks::AccountIterator;
use zolana_interface::{
    error::ShieldedPoolError, state::discriminator::TREE_ACCOUNT_DISCRIMINATOR,
    PENDING_NULLIFIERS_SEED,
};
use zolana_tree::{pending_nullifiers::PendingNullifiers, TreeAccount};

use super::{
    create_tree::allocate::{create_account, fund_tree, grow_tree, is_unallocated},
    protocol_config::loader::load_and_validate_protocol_authority,
    shared::{tree_error, verify_pda},
};

pub fn process_pending_nullifiers(accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    if !data.is_empty() {
        return Err(ProgramError::InvalidInstructionData);
    }
    let mut iter = AccountIterator::new(accounts);
    let payer = iter.next_signer("payer")?;
    let authority = iter.next_signer("authority")?;
    let config = iter.next_account("protocol_config")?;
    let tree = iter.next_mut("tree")?;
    let table = iter.next_mut("pending_nullifiers")?;
    let system = iter.next_account("system_program")?;
    if !pinocchio_system::check_id(system.address()) {
        return Err(ProgramError::IncorrectProgramId);
    }
    load_and_validate_protocol_authority(config, authority)?;
    let address = tree.address().to_bytes();
    let bump = verify_pda(
        table.address(),
        &[PENDING_NULLIFIERS_SEED, &address],
        &crate::ID,
    )?;
    let mut tree = TreeAccount::from_account_view_mut_allow_paused(
        tree,
        &crate::ID,
        TREE_ACCOUNT_DISCRIMINATOR,
    )
    .map_err(tree_error)?;
    if tree.uses_compact_nullifiers() {
        return Err(ShieldedPoolError::InvalidPendingNullifiers.into());
    }
    let size = PendingNullifiers::account_size(tree.nullifier_tree().batch_size)
        .filter(|size| *size <= 10 * 1024 * 1024)
        .ok_or(ShieldedPoolError::InvalidPendingNullifiers)?;
    let lamports = Rent::get()?.try_minimum_balance(size)?;
    if is_unallocated(table) {
        let bump = [bump];
        let seeds = [
            Seed::from(PENDING_NULLIFIERS_SEED),
            Seed::from(&address),
            Seed::from(&bump),
        ];
        create_account(payer, table, &seeds, size, lamports)?;
    } else {
        grow_tree(table, size)?;
    }
    if table.data_len() != size {
        return Ok(());
    }
    fund_tree(payer, table, lamports)?;
    // This PDA has only been allocated and grown; no instruction can write its entries yet.
    PendingNullifiers::init_zeroed(&mut table.try_borrow_mut()?, &address)
        .map_err(|_| ShieldedPoolError::InvalidPendingNullifiers)?;
    // Discard roots that predate legacy spends before starting with an empty table.
    tree.enable_compact_nullifiers().map_err(tree_error)
}
