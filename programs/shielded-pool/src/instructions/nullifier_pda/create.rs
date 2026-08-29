use borsh::BorshSerialize;
use light_program_profiler::profile;
use pinocchio::{
    cpi::{Seed, Signer},
    error::ProgramError,
    sysvars::{rent::Rent, Sysvar},
    AccountView, ProgramResult,
};
use pinocchio_system::instructions::{Allocate, Assign};
use zolana_interface::{
    error::ShieldedPoolError, event::Input, NullifierPda, NULLIFIER_PDA_SEED, NULLIFIER_PDA_SIZE,
};

use super::loader::load_unused_nullifier_pda;

pub(crate) struct NullifierPdaRent {
    nullifier_pda_minimum: u64,
    tree_minimum: u64,
}

impl NullifierPdaRent {
    fn missing(&self, nullifier_pda: &AccountView) -> u64 {
        self.nullifier_pda_minimum
            .saturating_sub(nullifier_pda.lamports())
    }

    fn tree_remaining(&self, tree: &AccountView, amount: u64) -> Result<u64, ProgramError> {
        tree.lamports()
            .checked_sub(amount)
            .filter(|remaining| *remaining >= self.tree_minimum)
            .ok_or_else(|| ShieldedPoolError::InsufficientNullifierPdaRent.into())
    }
}

#[inline(never)]
#[profile]
pub(crate) fn create_nullifier_pdas(
    tree: &AccountView,
    nullifier_pdas: &mut [&mut AccountView],
    inputs: &[Input],
) -> Result<NullifierPdaRent, ProgramError> {
    if nullifier_pdas.len() != inputs.len() {
        return Err(ShieldedPoolError::InvalidNullifierPda.into());
    }
    let rent_sysvar = Rent::get()?;
    let rent = NullifierPdaRent {
        nullifier_pda_minimum: rent_sysvar.try_minimum_balance(NULLIFIER_PDA_SIZE)?,
        tree_minimum: rent_sysvar.try_minimum_balance(tree.data_len())?,
    };
    let tree_address = *tree.address().as_array();
    let mut total_missing: u64 = 0;
    for (nullifier_pda, input) in nullifier_pdas.iter_mut().zip(inputs) {
        create_nullifier_pda(nullifier_pda, &tree_address, input)?;
        total_missing = total_missing
            .checked_add(rent.missing(nullifier_pda))
            .ok_or(ProgramError::ArithmeticOverflow)?;
    }
    rent.tree_remaining(tree, total_missing)?;
    Ok(rent)
}

#[inline(never)]
fn create_nullifier_pda(
    nullifier_pda: &mut AccountView,
    tree_address: &[u8; 32],
    input: &Input,
) -> ProgramResult {
    let bump = load_unused_nullifier_pda(nullifier_pda, tree_address, &input.nullifier)?;
    let bump_seed = [bump];
    let seeds = [
        Seed::from(NULLIFIER_PDA_SEED),
        Seed::from(tree_address.as_ref()),
        Seed::from(input.nullifier.as_ref()),
        Seed::from(bump_seed.as_ref()),
    ];
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

    let mut data = nullifier_pda
        .try_borrow_mut()
        .map_err(|_| ShieldedPoolError::InvalidNullifierPda)?;
    let mut writer: &mut [u8] = &mut data;
    NullifierPda {
        queue_index: input.input_queue_seq,
        bump,
    }
    .serialize(&mut writer)
    .map_err(|_| ShieldedPoolError::InvalidNullifierPda.into())
}

#[inline(never)]
#[profile]
pub(crate) fn fund_nullifier_pdas(
    tree: &mut AccountView,
    nullifier_pdas: &mut [&mut AccountView],
    rent: &NullifierPdaRent,
) -> ProgramResult {
    for nullifier_pda in nullifier_pdas.iter_mut() {
        let missing = rent.missing(nullifier_pda);
        if missing == 0 {
            continue;
        }
        let tree_remaining = rent.tree_remaining(tree, missing)?;
        let nullifier_pda_balance = nullifier_pda
            .lamports()
            .checked_add(missing)
            .ok_or(ProgramError::ArithmeticOverflow)?;
        tree.set_lamports(tree_remaining);
        nullifier_pda.set_lamports(nullifier_pda_balance);
    }
    Ok(())
}
