use crate::instructions::shared::caused_by;
use light_program_profiler::profile;
use pinocchio::{
    cpi::{Seed, Signer},
    error::ProgramError,
    sysvars::{rent::Rent, Sysvar},
    AccountView, ProgramResult,
};
use pinocchio_system::instructions::{Allocate, Assign, CreateAccount, Transfer};
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
        let nullifier_pda_balance = nullifier_pda
            .lamports()
            .checked_add(missing)
            .ok_or(ProgramError::ArithmeticOverflow)?;
        tree.set_lamports(tree_remaining);
        nullifier_pda.set_lamports(nullifier_pda_balance);
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
/// The fee rides on the first PDA's `CreateAccount` (payer -> PDA) and is then
/// moved to the tree directly, which saves a Transfer CPI. Only when the first
/// PDA was pre-funded (Allocate + Assign, no payer leg) does the fee fall back
/// to a Transfer CPI. That CPI includes the tree, so it must run before any
/// direct tree lamport move: a CPI boundary syncs only its own accounts into the
/// transaction context, and a pending tree debit without the matching nullifier
/// PDA credits trips the runtime's UnbalancedInstruction check. Both fee paths
/// therefore run on the first PDA, before its rent top-up.
#[inline(never)]
#[profile]
pub(crate) fn create_nullifier_pdas<'n>(
    payer: &AccountView,
    tree: &mut AccountView,
    nullifier_pdas: &mut [&mut AccountView],
    nullifiers: impl ExactSizeIterator<Item = &'n [u8; 32]>,
    input_tree: &InputTreeResult,
) -> ProgramResult {
    if nullifier_pdas.len() != nullifiers.len() {
        return Err(ShieldedPoolError::InvalidNullifierPda.into());
    }
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
    let forester_fee = input_tree.forester_fee;

    let mut pdas = nullifier_pdas.iter_mut().zip(nullifiers);
    let Some((first_pda, first_nullifier)) = pdas.next() else {
        return collect_forester_fee(payer, tree, forester_fee);
    };
    let fee_in_pda = if first_pda.lamports() == 0 {
        forester_fee
    } else {
        0
    };
    CreateNullifierPda {
        tree_address,
        nullifier: first_nullifier,
        record: NullifierPda {
            queue_index: first_queue_index,
            tree_id: input_tree.tree_id,
        },
        lamports: fee_in_pda,
    }
    .execute(payer, first_pda)?;
    if fee_in_pda == 0 {
        collect_forester_fee(payer, tree, forester_fee)?;
    } else {
        let tree_balance = tree
            .lamports()
            .checked_add(fee_in_pda)
            .ok_or(ProgramError::ArithmeticOverflow)?;
        let pda_balance = first_pda
            .lamports()
            .checked_sub(fee_in_pda)
            .ok_or(ProgramError::ArithmeticOverflow)?;
        tree.set_lamports(tree_balance);
        first_pda.set_lamports(pda_balance);
    }
    rent.top_up(tree, first_pda)?;

    for (position, (nullifier_pda, nullifier)) in (1u64..).zip(pdas) {
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
            lamports: 0,
        }
        .execute(payer, nullifier_pda)?;
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
    /// Funds the account from the payer on the hot path only; a pre-funded PDA
    /// keeps its balance and is allocated and assigned in place.
    lamports: u64,
}

impl CreateNullifierPda<'_> {
    #[inline(never)]
    fn execute(self, payer: &AccountView, nullifier_pda: &mut AccountView) -> ProgramResult {
        let bump = load_unused_nullifier_pda(nullifier_pda, self.tree_address, self.nullifier)?;
        let bump_seed = [bump];
        let seeds = [
            Seed::from(NULLIFIER_PDA_SEED),
            Seed::from(self.tree_address.as_ref()),
            Seed::from(self.nullifier.as_ref()),
            Seed::from(bump_seed.as_ref()),
        ];
        if nullifier_pda.lamports() == 0 {
            CreateAccount {
                from: payer,
                to: nullifier_pda,
                lamports: self.lamports,
                space: NULLIFIER_PDA_SIZE as u64,
                owner: &crate::ID,
            }
            .invoke_signed(&[Signer::from(&seeds)])?;
        } else {
            Allocate {
                account: nullifier_pda,
                space: NULLIFIER_PDA_SIZE as u64,
            }
            .invoke_signed(&[Signer::from(&seeds)])?;
            Assign {
                account: nullifier_pda,
                owner: &crate::ID,
            }
            .invoke_signed(&[Signer::from(&seeds)])?;
        }

        let mut data = nullifier_pda
            .try_borrow_mut()
            .map_err(caused_by(ShieldedPoolError::InvalidNullifierPda))?;
        self.record
            .write_to(&mut data)
            .ok_or(ShieldedPoolError::InvalidNullifierPda.into())
    }
}
