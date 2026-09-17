use borsh::BorshDeserialize;
use pinocchio::{error::ProgramError, AccountView, ProgramResult};
use zolana_account_checks::AccountIterator;
use zolana_interface::{
    direct_spend::{
        InlineSpend, PaymentInputs, ADMITTED_PAYMENT_DOMAIN, INLINE_BINDING, INLINE_INPUTS,
    },
    error::ShieldedPoolError,
};

use super::{
    commit::{emit_events, NotesProof, Spend},
    tree_layout,
};
use crate::instructions::nullifier_pda::uses_nullifier_filter;

/// Accounts: owner (signer), input tree, output tree, pending nullifiers,
/// nullifier filter, system program, this program. The admitted payment is
/// carried in the instruction and settles in this transaction; there is no
/// buffer, so `INLINE_BINDING` takes the buffer's place in the intent and the
/// certificate id.
#[light_program_profiler::profile]
pub fn process_inline(accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    let ix = InlineSpend::try_from_slice(data).map_err(|_| ProgramError::InvalidInstructionData)?;
    let mut iter = AccountIterator::new(accounts);
    let owner = iter.next_signer("owner")?;
    let input_tree = iter.next_mut("input_tree")?;
    let output_tree = iter.next_mut("output_tree")?;
    let pending = iter.next_mut("pending_nullifiers")?;
    if !uses_nullifier_filter(input_tree)? {
        return Err(ShieldedPoolError::InvalidNullifierFilter.into());
    }
    let filter = iter.next_mut("nullifier_filter")?;
    let system = iter.next_account("system_program")?;
    let program = iter.next_account("shielded_pool_program")?;
    if !pinocchio_system::check_id(system.address()) || program.address() != &crate::ID {
        return Err(ProgramError::IncorrectProgramId);
    }
    if !iter.remaining_unchecked_mut()?.is_empty() {
        return Err(ProgramError::InvalidArgument);
    }

    let input_tree_address = input_tree.address().to_bytes();
    let state_root = {
        let bytes = input_tree.try_borrow()?;
        let tree = tree_layout(input_tree, &bytes)?;
        tree.utxo
            .root_by_index(ix.state_root_index)
            .map_err(|_| ProgramError::InvalidArgument)?
    };
    let statement = ix.payment(
        owner.address().as_array(),
        &input_tree_address,
        &output_tree.address().to_bytes(),
        state_root,
    );
    let mut spend = Spend {
        owner,
        input_tree,
        output_tree,
        pending,
        filter: Some(filter),
    };
    let output_tree_id = spend.check_statement(&statement)?;
    let intent = statement.intent(owner.address().as_array(), &INLINE_BINDING)?;
    let PaymentInputs::Notes {
        certificate,
        freshness,
    } = &statement.inputs
    else {
        return Err(ProgramError::InvalidArgument);
    };
    {
        let bytes = spend.input_tree.try_borrow()?;
        let tree = tree_layout(spend.input_tree, &bytes)?;
        NotesProof {
            statement: &statement,
            certificate,
            freshness,
            proof: &ix.proof,
            commitment: Some(&ix.commitment),
            capacity: INLINE_INPUTS,
            domain: ADMITTED_PAYMENT_DOMAIN,
            owner: owner.address().as_array(),
            binding: &INLINE_BINDING,
            input_tree: tree,
            input_tree_address: &input_tree_address,
            output_tree_id,
            intent,
        }
        .verify()?;
    }
    let settled = spend.settle(&certificate.nullifiers, &statement, true)?;
    emit_events(&statement, &certificate.nullifiers, &settled)
}
