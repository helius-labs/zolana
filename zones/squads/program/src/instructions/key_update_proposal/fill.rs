//! `fill_key_update` (tag 7): the executor appends a chunk of new shared-key
//! ciphertexts to the proposal buffer.

use pinocchio::{
    sysvars::{rent::Rent, Sysvar},
    AccountView, ProgramResult, Resize,
};
use zolana_squads_interface::{
    error::SquadsZoneError, instruction::instruction_data::FillKeyUpdateIxData,
};

use super::loader::load_key_update_proposal;

/// `fill_key_update` (tag 7): the executor appends a chunk of new shared-key
/// ciphertexts to the proposal buffer.
///
/// Accounts: `[executor (signer, writable, fee payer), key_update_proposal
/// (writable)]`.
///
/// The proposal account was funded for the full buffer at creation, so this
/// instruction (which has no system program) only grows the data length into
/// rent already paid. The grow is bounded by the funded rent: if the new
/// serialized length would require more rent than the account holds, it is
/// rejected as a buffer overflow.
#[inline(never)]
pub fn process_fill_key_update_ix(accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    if accounts.len() < 2 {
        return Err(SquadsZoneError::InvalidInstructionData.into());
    }
    let (executor, rest) = accounts
        .split_first_mut()
        .ok_or(SquadsZoneError::InvalidInstructionData)?;
    let key_update_proposal = rest
        .first_mut()
        .ok_or(SquadsZoneError::InvalidInstructionData)?;

    if !executor.is_signer() {
        return Err(SquadsZoneError::MissingExecutorSignature.into());
    }

    let mut proposal = load_key_update_proposal(key_update_proposal)?;
    if executor.address() != &proposal.executor {
        return Err(SquadsZoneError::ExecutorMismatch.into());
    }

    let ix = FillKeyUpdateIxData::deserialize(data)
        .map_err(|_| SquadsZoneError::InvalidInstructionData)?;

    proposal
        .new_key_ciphertexts
        .extend_from_slice(&ix.ciphertexts);

    let bytes = proposal
        .serialize()
        .map_err(|_| SquadsZoneError::Deserialization)?;

    // The buffer grows only into rent already funded at creation. Reject any
    // append that would push the serialized length past what the account's
    // lamport balance can keep rent-exempt.
    let required = Rent::get()?.try_minimum_balance(bytes.len())?;
    if key_update_proposal.lamports() < required {
        return Err(SquadsZoneError::KeyBufferOverflow.into());
    }

    key_update_proposal
        .resize(bytes.len())
        .map_err(|_| SquadsZoneError::InvalidAccountSize)?;
    {
        let mut account_data = key_update_proposal
            .try_borrow_mut()
            .map_err(|_| SquadsZoneError::InvalidKeyUpdateProposal)?;
        let slot = account_data
            .get_mut(..bytes.len())
            .ok_or(SquadsZoneError::InvalidAccountSize)?;
        slot.copy_from_slice(&bytes);
    }

    Ok(())
}
