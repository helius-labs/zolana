use crate::instructions::shared::caused_by;
use borsh::BorshSerialize;
use light_program_profiler::profile;
use pinocchio::{
    cpi::{Seed, Signer},
    error::ProgramError,
    sysvars::{rent::Rent, Sysvar},
    AccountView, ProgramResult,
};
use pinocchio_system::instructions::CreateAccountAllowPrefund;
use zolana_interface::{
    error::ShieldedPoolError, NullifierPda, NULLIFIER_PDA_SEED, NULLIFIER_PDA_SIZE,
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

pub(crate) struct InputTreeResult {
    /// Queue index the first input took. The rest follow at `first + i`:
    /// `queue_next_index` is a single monotone counter and the insert loop walks
    /// one tree in instruction order.
    pub first_input_queue_seq: u64,
    pub forester_fee: u64,
    pub fee_balance: u64,
    pub tree_id: u16,
}

#[inline(never)]
#[profile]
/// `nullifier_pdas` is an iterator rather than a slice because the two callers
/// reach their mutable account slices through different parsed account structs.
///
/// `nullifiers` are the instruction's own nullifiers, in order. Each PDA records
/// the queue index its nullifier took, derived as `first_input_queue_seq + i`
/// rather than carried in a vector.
pub(crate) fn create_nullifier_pdas<'a, 'n>(
    tree: &mut AccountView,
    nullifier_pdas: impl ExactSizeIterator<Item = &'a mut AccountView>,
    nullifiers: impl ExactSizeIterator<Item = &'n [u8; 32]>,
    input_tree: &InputTreeResult,
) -> ProgramResult {
    if nullifier_pdas.len() != nullifiers.len() {
        return Err(ShieldedPoolError::InvalidNullifierPda.into());
    }
    let mut nullifier_pdas = nullifier_pdas;
    let rent_sysvar = Rent::get()?;
    let rent = NullifierPdaRent {
        nullifier_pda_minimum: rent_sysvar.try_minimum_balance(NULLIFIER_PDA_SIZE)?,
        tree_minimum: rent_sysvar
            .try_minimum_balance(tree.data_len())?
            .checked_add(input_tree.fee_balance)
            .ok_or(ProgramError::ArithmeticOverflow)?,
    };
    let tree_address = *tree.address().as_array();
    for (index, (nullifier_pda, nullifier)) in nullifier_pdas.by_ref().zip(nullifiers).enumerate() {
        let queue_index = input_tree
            .first_input_queue_seq
            .checked_add(index as u64)
            .ok_or(ProgramError::ArithmeticOverflow)?;
        create_nullifier_pda(
            nullifier_pda,
            &tree_address,
            input_tree.tree_id,
            nullifier,
            queue_index,
        )?;
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
    nullifier_pda: &mut AccountView,
    tree_address: &[u8; 32],
    tree_id: u16,
    nullifier: &[u8; 32],
    queue_index: u64,
) -> ProgramResult {
    let bump = load_unused_nullifier_pda(nullifier_pda, tree_address, nullifier)?;
    let bump_seed = [bump];
    let seeds = [
        Seed::from(NULLIFIER_PDA_SEED),
        Seed::from(tree_address.as_ref()),
        Seed::from(nullifier.as_ref()),
        Seed::from(bump_seed.as_ref()),
    ];
    // One System Program CPI for both empty and prefunded addresses. Using
    // Allocate + Assign for the prefunded case would consume two trace entries
    // per input and make the supported 36-input shape exceed Solana's 64-entry
    // instruction-trace limit.
    CreateAccountAllowPrefund {
        to: nullifier_pda,
        space: NULLIFIER_PDA_SIZE as u64,
        owner: &crate::ID,
        funding: None,
    }
    .invoke_signed(&[Signer::from(&seeds)])?;

    let mut data = nullifier_pda
        .try_borrow_mut()
        .map_err(caused_by(ShieldedPoolError::InvalidNullifierPda))?;
    let mut writer: &mut [u8] = &mut data;
    NullifierPda {
        queue_index,
        tree_id,
    }
    .serialize(&mut writer)
    .map_err(caused_by(ShieldedPoolError::InvalidNullifierPda))
}
