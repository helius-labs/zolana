//! `EMIT_EVENT` self-CPI: the program re-invokes itself with the encoded event
//! as instruction data and no accounts, so the event lands in the transaction's
//! inner-instruction log for indexers to read.

use pinocchio::{
    address::address_eq, cpi::invoke, error::ProgramError, instruction::InstructionView,
    AccountView, ProgramResult,
};
use zolana_squads_interface::{
    error::SquadsZoneError,
    event::{
        encode_event_instruction, KeyRotationEvent, SquadsEventKind, ViewingKeyAccountClosedEvent,
    },
};

/// Every emit path must run this first. Without the executable and id check a
/// caller could point the emit at another program and have the zone invoke it.
#[inline(always)]
pub fn validate_zone_program(program: &AccountView) -> Result<(), ProgramError> {
    if !program.executable() || !address_eq(program.address(), &crate::ID) {
        return Err(SquadsZoneError::InvalidZoneProgram.into());
    }
    Ok(())
}

/// Record the pre-rotation viewing key account. Must run before
/// `execute_key_update` overwrites it.
#[inline(never)]
pub fn emit_key_rotation_event(event: &KeyRotationEvent) -> ProgramResult {
    let data = encode_event_instruction(SquadsEventKind::KeyRotation, event)
        .map_err(|_| SquadsZoneError::Serialization)?;
    emit_encoded_event(&data)
}

/// Record the prior viewing key account. Must run before
/// `close_viewing_key_account` zeroes it.
#[inline(never)]
pub fn emit_viewing_key_account_closed_event(
    event: &ViewingKeyAccountClosedEvent,
) -> ProgramResult {
    let data = encode_event_instruction(SquadsEventKind::ViewingKeyAccountClosed, event)
        .map_err(|_| SquadsZoneError::Serialization)?;
    emit_encoded_event(&data)
}

#[inline(never)]
fn emit_encoded_event(data: &[u8]) -> ProgramResult {
    let instruction = InstructionView {
        program_id: &crate::ID,
        accounts: &[],
        data,
    };
    let accounts: [&AccountView; 0] = [];
    invoke(&instruction, &accounts)
}
