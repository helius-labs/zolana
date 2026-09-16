use crate::instructions::shared::caused_by;
use light_program_profiler::profile;
use pinocchio::{
    cpi::{Seed, Signer},
    error::ProgramError,
    sysvars::{rent::Rent, Sysvar},
    AccountView, ProgramResult, Resize,
};
use pinocchio_system::instructions::{Assign, Transfer};
use zolana_interface::{
    error::ShieldedPoolError, event::InputTreeSequence, NullifierPda, NULLIFIER_PDA_SEED,
    NULLIFIER_PDA_SIZE,
};

use super::loader::load_unused_nullifier_pda;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum NullifierAdmission {
    ExactProof,
    FilterNegative,
}

struct NullifierPdaRent {
    nullifier_pda_minimum: u64,
    tree_minimum: u64,
}

impl NullifierPdaRent {
    /// Move `nullifier_pda`'s missing rent from the tree, keeping the tree at or
    /// above its own rent minimum plus the fee balance it owes foresters.
    #[inline(always)]
    fn top_up(&self, tree: &mut AccountView, nullifier_pda: &mut AccountView) -> ProgramResult {
        let missing = self
            .nullifier_pda_minimum
            .saturating_sub(nullifier_pda.lamports());
        if missing == 0 {
            return Ok(());
        }
        let tree_remaining = tree
            .lamports()
            .checked_sub(missing)
            .filter(|remaining| *remaining >= self.tree_minimum)
            .ok_or(ShieldedPoolError::InsufficientNullifierPdaRent)?;
        tree.set_lamports(tree_remaining);
        nullifier_pda.set_lamports(self.nullifier_pda_minimum);
        Ok(())
    }
}

/// What the input tree assigned while its nullifiers were queued. Queue inserts
/// are sequential within one instruction, so input `i` took
/// `input_tree.first_input_queue_seq + i`; the event relies on the same fact.
pub(crate) struct InputTreeResult {
    pub input_tree: InputTreeSequence,
    pub forester_fee: u64,
    pub fee_balance: u64,
    pub tree_id: u16,
}

#[inline(never)]
#[profile]
pub(crate) fn create_nullifier_pdas<'n>(
    payer: &AccountView,
    tree: &mut AccountView,
    nullifier_pdas: &mut [&mut AccountView],
    nullifiers: impl Iterator<Item = &'n [u8; 32]>,
    input_tree: &InputTreeResult,
    admission: NullifierAdmission,
) -> ProgramResult {
    if uses_pending_nullifiers(tree)? {
        return consume_pending_nullifiers(
            payer,
            tree,
            nullifier_pdas,
            nullifiers,
            input_tree,
            admission,
        );
    }
    if admission == NullifierAdmission::FilterNegative {
        return Err(ShieldedPoolError::InvalidNullifierFilter.into());
    }
    let rent_sysvar = Rent::get()?;
    let rent = NullifierPdaRent {
        nullifier_pda_minimum: rent_sysvar.try_minimum_balance(NULLIFIER_PDA_SIZE)?,
        tree_minimum: rent_sysvar
            .try_minimum_balance(tree.data_len())?
            .checked_add(input_tree.fee_balance)
            .ok_or(ProgramError::ArithmeticOverflow)?,
    };
    let tree_address = tree.address().to_bytes();
    let first_queue_index = input_tree.input_tree.first_input_queue_seq;
    collect_forester_fee(payer, tree, input_tree.forester_fee)?;

    for (position, (nullifier_pda, nullifier)) in
        (0u64..).zip(nullifier_pdas.iter_mut().zip(nullifiers))
    {
        let queue_index = first_queue_index
            .checked_add(position)
            .ok_or(ProgramError::ArithmeticOverflow)?;
        NullifierPdaCreate {
            tree_address: &tree_address,
            nullifier,
            record: NullifierPda {
                queue_index,
                tree_id: input_tree.tree_id,
            },
        }
        .init(nullifier_pda)?;
        rent.top_up(tree, nullifier_pda)?;
    }
    Ok(())
}

#[inline(never)]
fn collect_forester_fee(payer: &AccountView, tree: &AccountView, amount: u64) -> ProgramResult {
    if amount == 0 {
        return Ok(());
    }
    Transfer {
        from: payer,
        to: tree,
        lamports: amount,
    }
    .invoke()
}

struct NullifierPdaCreate<'a> {
    tree_address: &'a [u8; 32],
    nullifier: &'a [u8; 32],
    record: NullifierPda,
}

impl NullifierPdaCreate<'_> {
    #[inline(never)]
    fn init(self, nullifier_pda: &mut AccountView) -> ProgramResult {
        let bump = load_unused_nullifier_pda(nullifier_pda, self.tree_address, self.nullifier)?;
        let bump_seed = [bump];
        let seeds = [
            Seed::from(NULLIFIER_PDA_SEED),
            Seed::from(self.tree_address.as_ref()),
            Seed::from(self.nullifier.as_ref()),
            Seed::from(bump_seed.as_ref()),
        ];
        Assign {
            account: nullifier_pda,
            owner: &crate::ID,
        }
        .invoke_signed(&[Signer::from(&seeds)])?;
        // SPP now owns the writable account, so it can allocate the record
        // directly, whether or not the address was pre-funded.
        nullifier_pda.resize(NULLIFIER_PDA_SIZE)?;

        let mut data = nullifier_pda
            .try_borrow_mut()
            .map_err(caused_by(ShieldedPoolError::InvalidNullifierPda))?;
        self.record
            .write_to(&mut data)
            .ok_or(ShieldedPoolError::InvalidNullifierPda.into())
    }
}

pub(crate) fn nullifier_account_count(
    tree: &AccountView,
    inputs: usize,
) -> Result<usize, ProgramError> {
    Ok(if uses_pending_nullifiers(tree)? {
        1 + usize::from(uses_nullifier_filter(tree)?)
    } else {
        inputs
    })
}

#[light_program_profiler::profile]
fn consume_pending_nullifiers<'n>(
    payer: &AccountView,
    tree: &mut AccountView,
    accounts: &mut [&mut AccountView],
    nullifiers: impl Iterator<Item = &'n [u8; 32]>,
    input: &InputTreeResult,
    admission: NullifierAdmission,
) -> ProgramResult {
    use zolana_tree::{
        pending_nullifiers::{PendingNullifierError, PendingNullifiers},
        TreeAccount,
    };
    let active = uses_nullifier_filter(tree)?;
    if accounts.len() != 1 + usize::from(active)
        || (admission == NullifierAdmission::FilterNegative && !active)
    {
        return Err(ShieldedPoolError::InvalidNullifierFilter.into());
    }
    let nullifiers: Vec<_> = nullifiers.copied().collect();
    let (table, history) = accounts
        .split_first_mut()
        .ok_or(ShieldedPoolError::InvalidPendingNullifiers)?;
    let tree_address = tree.address().to_bytes();
    crate::instructions::shared::verify_pda(
        table.address(),
        &[zolana_interface::PENDING_NULLIFIERS_SEED, &tree_address],
        &crate::ID,
    )?;
    if !table.owned_by(&crate::ID) || !table.is_writable() {
        return Err(ShieldedPoolError::InvalidPendingNullifiers.into());
    }
    let watermark = TreeAccount::from_account_view_mut(
        tree,
        &crate::ID,
        zolana_interface::state::discriminator::TREE_ACCOUNT_DISCRIMINATOR,
    )
    .map_err(crate::instructions::shared::tree_error)?
    .close_before_index();
    collect_forester_fee(payer, tree, input.forester_fee)?;
    let mut bytes = table.try_borrow_mut()?;
    let mut table = PendingNullifiers::from_bytes(&mut bytes, &tree_address)
        .map_err(|_| ShieldedPoolError::InvalidPendingNullifiers)?;
    let batch = table
        .insert_batch(
            &nullifiers,
            input.input_tree.first_input_queue_seq,
            watermark,
        )
        .map_err(|error| match error {
            PendingNullifierError::AlreadySpent => ShieldedPoolError::NullifierAlreadySpent,
            PendingNullifierError::Full => ShieldedPoolError::PendingNullifiersFull,
            _ => ShieldedPoolError::InvalidPendingNullifiers,
        })?;
    if active {
        use zolana_tree::nullifier_filter::{FilterError, NullifierFilter};
        let filter = &mut history[0];
        crate::instructions::shared::verify_pda(
            filter.address(),
            &[zolana_interface::NULLIFIER_FILTER_SEED, &tree_address],
            &crate::ID,
        )?;
        if !filter.owned_by(&crate::ID) || !filter.is_writable() {
            return Err(ShieldedPoolError::InvalidNullifierFilter.into());
        }
        NullifierFilter::from_bytes(&mut filter.try_borrow_mut()?, &tree_address)
            .map_err(|_| ShieldedPoolError::InvalidNullifierFilter)?
            .record_pending_batch(batch, admission == NullifierAdmission::ExactProof)
            .map_err(|error| match error {
                FilterError::NeedsProof => ShieldedPoolError::NullifierProofRequired,
                FilterError::Duplicate => ShieldedPoolError::NullifierAlreadySpent,
                _ => ShieldedPoolError::InvalidNullifierFilter,
            })?;
    }
    Ok(())
}

fn uses_pending_nullifiers(tree: &AccountView) -> Result<bool, ProgramError> {
    zolana_tree::TreeAccount::read_compact_nullifiers(&tree.try_borrow()?)
        .map_err(crate::instructions::shared::tree_error)
}

pub(crate) fn uses_nullifier_filter(tree: &AccountView) -> Result<bool, ProgramError> {
    Ok(
        zolana_tree::TreeAccount::read_nullifier_filter_mode(&tree.try_borrow()?)
            .map_err(crate::instructions::shared::tree_error)?
            == zolana_tree::NullifierFilterMode::Active,
    )
}
