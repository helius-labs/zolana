use borsh::BorshSerialize;
use light_program_profiler::profile;
use pinocchio::{
    cpi::{Seed, Signer},
    error::ProgramError,
    sysvars::{rent::Rent, Sysvar},
    AccountView, ProgramResult,
};
use pinocchio_system::instructions::{Allocate, Assign, CreateAccount};
use zolana_interface::{
    error::ShieldedPoolError, event::Input, NullifierPda, NULLIFIER_PDA_SEED, NULLIFIER_PDA_SIZE,
};

use super::loader::load_unused_nullifier_pda;

struct NullifierPdaRent {
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
    payer: &AccountView,
    tree: &mut AccountView,
    tree_id: u16,
    nullifier_pdas: &mut [&mut AccountView],
    inputs: &[Input],
) -> ProgramResult {
    if nullifier_pdas.len() != inputs.len() {
        return Err(ShieldedPoolError::InvalidNullifierPda.into());
    }
    let rent_sysvar = Rent::get()?;
    let rent = NullifierPdaRent {
        nullifier_pda_minimum: rent_sysvar.try_minimum_balance(NULLIFIER_PDA_SIZE)?,
        tree_minimum: rent_sysvar.try_minimum_balance(tree.data_len())?,
    };
    let tree_address = *tree.address().as_array();
    for (nullifier_pda, input) in nullifier_pdas.iter_mut().zip(inputs) {
        create_nullifier_pda(payer, nullifier_pda, &tree_address, tree_id, input)?;
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

#[inline(never)]
fn create_nullifier_pda(
    payer: &AccountView,
    nullifier_pda: &mut AccountView,
    tree_address: &[u8; 32],
    tree_id: u16,
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
    if nullifier_pda.lamports() == 0 {
        CreateAccount {
            from: payer,
            to: nullifier_pda,
            lamports: 0,
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
        .map_err(|_| ShieldedPoolError::InvalidNullifierPda)?;
    let mut writer: &mut [u8] = &mut data;
    NullifierPda {
        queue_index: input.input_queue_seq,
        tree_id,
    }
    .serialize(&mut writer)
    .map_err(|_| ShieldedPoolError::InvalidNullifierPda.into())
}
