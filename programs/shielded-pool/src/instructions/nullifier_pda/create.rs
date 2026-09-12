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

/// Create one nullifier PDA per queued nullifier and collect the tree's
/// forester fee from the payer in the same pass. The tree funds each PDA's
/// rent; the payer pays the fee.
///
/// Callers must supply one PDA per nullifier, in matching order: transact
/// splits an exact-length group and both merge parsers collect one PDA per
/// input. The zip below relies on those equal counts.
///
/// Collect the fee before any rent top-up: its Transfer CPI includes the tree,
/// and a CPI boundary syncs only its own accounts into the transaction context.
/// A pending tree debit without the matching nullifier PDA credits would trip
/// the runtime's UnbalancedInstruction check.
#[inline(never)]
#[profile]
pub(crate) fn create_nullifier_pdas<'n>(
    payer: &AccountView,
    tree: &mut AccountView,
    nullifier_pdas: &mut [&mut AccountView],
    nullifiers: impl Iterator<Item = &'n [u8; 32]>,
    input_tree: &InputTreeResult,
) -> ProgramResult {
    let rent_sysvar = Rent::get()?;
    let rent = NullifierPdaRent {
        nullifier_pda_minimum: rent_sysvar.try_minimum_balance(NULLIFIER_PDA_SIZE)?,
        tree_minimum: rent_sysvar
            .try_minimum_balance(tree.data_len())?
            .checked_add(input_tree.fee_balance)
            .ok_or(ProgramError::ArithmeticOverflow)?,
    };
    let tree_address = &input_tree.input_tree.tree;
    let first_queue_index = input_tree.input_tree.first_input_queue_seq;
    collect_forester_fee(payer, tree, input_tree.forester_fee)?;

    for (position, (nullifier_pda, nullifier)) in
        (0u64..).zip(nullifier_pdas.iter_mut().zip(nullifiers))
    {
        let queue_index = first_queue_index
            .checked_add(position)
            .ok_or(ProgramError::ArithmeticOverflow)?;
        CreateNullifierPda {
            tree_address,
            nullifier,
            record: NullifierPda {
                queue_index,
                tree_id: input_tree.tree_id,
            },
        }
        .execute(nullifier_pda)?;
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

struct CreateNullifierPda<'a> {
    tree_address: &'a [u8; 32],
    nullifier: &'a [u8; 32],
    record: NullifierPda,
}

impl CreateNullifierPda<'_> {
    #[inline(never)]
    fn execute(self, nullifier_pda: &mut AccountView) -> ProgramResult {
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
