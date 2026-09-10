use crate::instructions::shared::caused_by;
use borsh::BorshSerialize;
use light_program_profiler::profile;
use pinocchio::{
    cpi::{Seed, Signer},
    error::ProgramError,
    sysvars::{rent::Rent, Sysvar},
    AccountView, ProgramResult,
};
use pinocchio_system::instructions::{Allocate, Assign, CreateAccount, Transfer};
use zolana_interface::{
    error::ShieldedPoolError, event::Input, NullifierPda, NULLIFIER_PDA_SEED, NULLIFIER_PDA_SIZE,
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

pub(crate) struct InputTreeResult {
    pub inputs: Vec<Input>,
    pub forester_fee: u64,
    pub fee_balance: u64,
    pub tree_id: u16,
}

/// Create the nullifier PDAs and collect the tree's forester fee from the
/// payer in the same pass. The tree funds each PDA's rent; the payer pays the
/// fee.
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
pub(crate) fn create_nullifier_pdas(
    payer: &AccountView,
    tree: &mut AccountView,
    nullifier_pdas: &mut [&mut AccountView],
    input_tree: &InputTreeResult,
) -> ProgramResult {
    if nullifier_pdas.len() != input_tree.inputs.len() {
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
    let tree_address = *tree.address().as_array();
    let tree_id = input_tree.tree_id;
    let forester_fee = input_tree.forester_fee;

    let mut pdas = nullifier_pdas.iter_mut().zip(&input_tree.inputs);
    let Some((first_pda, first_input)) = pdas.next() else {
        return collect_forester_fee(payer, tree, forester_fee);
    };
    let fee_in_pda = if first_pda.lamports() == 0 {
        forester_fee
    } else {
        0
    };
    create_nullifier_pda(
        payer,
        first_pda,
        &tree_address,
        tree_id,
        first_input,
        fee_in_pda,
    )?;
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

    for (nullifier_pda, input) in pdas {
        create_nullifier_pda(payer, nullifier_pda, &tree_address, tree_id, input, 0)?;
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

/// `lamports` funds the account from the payer on the hot path only; a
/// pre-funded PDA keeps its balance and is allocated and assigned in place.
#[inline(never)]
fn create_nullifier_pda(
    payer: &AccountView,
    nullifier_pda: &mut AccountView,
    tree_address: &[u8; 32],
    tree_id: u16,
    input: &Input,
    lamports: u64,
) -> ProgramResult {
    let bump = load_unused_nullifier_pda(nullifier_pda, tree_address, &input.nullifier)?;
    let bump_seed = [bump];
    let seeds = [
        Seed::from(NULLIFIER_PDA_SEED),
        Seed::from(tree_address.as_ref()),
        Seed::from(input.nullifier.as_ref()),
        Seed::from(bump_seed.as_ref()),
    ];
    if nullifier_pda.lamports() == 0 {
        CreateAccount {
            from: payer,
            to: nullifier_pda,
            lamports,
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
    let mut writer: &mut [u8] = &mut data;
    NullifierPda {
        queue_index: input.input_queue_seq,
        tree_id,
    }
    .serialize(&mut writer)
    .map_err(caused_by(ShieldedPoolError::InvalidNullifierPda))
}
