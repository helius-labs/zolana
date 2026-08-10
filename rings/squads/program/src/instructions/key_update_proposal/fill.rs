//! `fill_key_update` (tag 7): the executor appends a chunk of new shared-key
//! ciphertexts to the proposal buffer.

use pinocchio::{
    sysvars::{clock::Clock, rent::Rent, Sysvar},
    AccountView, ProgramResult, Resize,
};
use zolana_squads_interface::{
    error::SquadsRingError, instruction::instruction_data::FillKeyUpdateIxData,
};

use super::loader::load_key_update_proposal;

/// Accounts: `[executor (signer, writable, fee payer), key_update_proposal
/// (writable)]`.
#[inline(never)]
pub fn process_fill_key_update_ix(accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    if accounts.len() < 2 {
        return Err(SquadsRingError::InvalidInstructionData.into());
    }
    let (executor, rest) = accounts
        .split_first_mut()
        .ok_or(SquadsRingError::InvalidInstructionData)?;
    let key_update_proposal = rest
        .first_mut()
        .ok_or(SquadsRingError::InvalidInstructionData)?;

    if !executor.is_signer() {
        return Err(SquadsRingError::MissingExecutorSignature.into());
    }

    let mut proposal = load_key_update_proposal(key_update_proposal)?;
    if executor.address() != &proposal.executor {
        return Err(SquadsRingError::ExecutorMismatch.into());
    }
    if Clock::get()?.unix_timestamp > proposal.expiry {
        return Err(SquadsRingError::ProposalExpired.into());
    }

    let ix = FillKeyUpdateIxData::deserialize(data)
        .map_err(|_| SquadsRingError::InvalidInstructionData)?;

    proposal
        .new_key_ciphertexts
        .extend_from_slice(&ix.ciphertexts);

    let bytes = proposal
        .serialize()
        .map_err(|_| SquadsRingError::Serialization)?;

    // The buffer grows only into rent already funded at creation. Reject any
    // append that would push the serialized length past what the account's
    // lamport balance can keep rent-exempt.
    let required = Rent::get()?.try_minimum_balance(bytes.len())?;
    if key_update_proposal.lamports() < required {
        return Err(SquadsRingError::KeyBufferOverflow.into());
    }

    key_update_proposal
        .resize(bytes.len())
        .map_err(|_| SquadsRingError::InvalidAccountSize)?;
    {
        let mut account_data = key_update_proposal
            .try_borrow_mut()
            .map_err(|_| SquadsRingError::InvalidKeyUpdateProposal)?;
        let slot = account_data
            .get_mut(..bytes.len())
            .ok_or(SquadsRingError::InvalidAccountSize)?;
        slot.copy_from_slice(&bytes);
    }

    Ok(())
}
