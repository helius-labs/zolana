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
    nullifier_filter::{
        NullifierFilter, DEFAULT_BIT_BYTES, DEFAULT_HASHES, MAX_CHECKPOINT_BACKLOG,
    },
    pending_nullifiers::PendingNullifiers,
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

/// Pending-table slots one checkpoint step scans.
pub const CHECKPOINT_SCAN_SLOTS: usize = 32_768;

/// Accounts: tree, pending nullifiers, nullifier filter (writable). Anyone
/// may call it, repeatedly, until the filter is settled again.
///
/// The first call moves the checkpoint to the tree's current nullifier root
/// and `next_index` and clears the bits; every call then scans a chunk of the
/// pending table and re-records the nullifiers queued at or after
/// `next_index`, which the tree does not hold yet. Filter-negative spends are
/// refused until the scan is complete. If the tree's `close_before_index`
/// moved during the rebuild, the pending table may have dropped an entry the
/// scan had not reached, so the rebuild starts over.
pub fn checkpoint(accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    if !data.is_empty() {
        return Err(ProgramError::InvalidInstructionData);
    }
    let mut iter = AccountIterator::new(accounts);
    let tree = iter.next_account("tree")?;
    let pending = iter.next_account("pending_nullifiers")?;
    let filter = iter.next_mut("nullifier_filter")?;
    if !iter.remaining_unchecked_mut()?.is_empty() {
        return Err(ProgramError::InvalidArgument);
    }
    let address = tree.address().to_bytes();
    for (account, seed) in [
        (&*pending, zolana_interface::PENDING_NULLIFIERS_SEED),
        (&*filter, NULLIFIER_FILTER_SEED),
    ] {
        verify_pda(account.address(), &[seed, &address], &crate::ID)?;
        if !account.owned_by(&crate::ID) {
            return Err(ShieldedPoolError::InvalidNullifierFilter.into());
        }
    }
    let (root, next_index, close_before) = {
        let bytes = tree.try_borrow()?;
        if !tree.owned_by(&crate::ID) {
            return Err(ProgramError::IllegalOwner);
        }
        if TreeAccount::read_nullifier_filter_mode(&bytes).map_err(tree_error)?
            != NullifierFilterMode::Active
        {
            return Err(ShieldedPoolError::InvalidNullifierFilter.into());
        }
        let layout = TreeAccount::read_layout(&bytes).map_err(tree_error)?;
        if layout.discriminator != TREE_ACCOUNT_DISCRIMINATOR {
            return Err(ShieldedPoolError::InvalidTreeAccounts.into());
        }
        (
            layout
                .nullifier
                .get_root()
                .ok_or(ShieldedPoolError::InvalidTreeAccounts)?,
            layout.nullifier.next_index,
            layout.nullifier.close_before_index,
        )
    };
    let mut filter_bytes = filter.try_borrow_mut()?;
    let mut filter = NullifierFilter::from_bytes(&mut filter_bytes, &address)
        .map_err(|_| ShieldedPoolError::InvalidNullifierFilter)?;
    if filter.is_settled() || filter.rebuild_close_before() != close_before {
        filter
            .begin_checkpoint(root, next_index, close_before)
            .map_err(|_| ShieldedPoolError::InvalidNullifierFilter)?;
    }
    let start = usize::try_from(filter.rebuild_cursor() - 1)
        .map_err(|_| ShieldedPoolError::InvalidNullifierFilter)?;
    let (backlog, next_slot) = {
        let mut bytes = pending.try_borrow_mut()?;
        PendingNullifiers::from_bytes(&mut bytes, &address)
            .map_err(|_| ShieldedPoolError::InvalidPendingNullifiers)?
            .queued_since(filter.checkpoint_index(), start, CHECKPOINT_SCAN_SLOTS)
    };
    if backlog.len() > MAX_CHECKPOINT_BACKLOG {
        return Err(ShieldedPoolError::NullifierFilterBacklog.into());
    }
    filter
        .record_backlog(&backlog, next_slot)
        .map_err(|_| ShieldedPoolError::InvalidNullifierFilter.into())
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
