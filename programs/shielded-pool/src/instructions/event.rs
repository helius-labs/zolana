use borsh::BorshSerialize;
use pinocchio::{cpi::invoke, instruction::InstructionView, AccountView, ProgramResult};
use zolana_interface::event::{
    encode_event_instruction, encode_event_instruction_with, EventKind, GeneralEvent,
};

/// Emit an encoded event by self-CPI: the program re-invokes itself with the
/// encoded event as instruction data and no accounts, so the event is recorded
/// in the transaction's inner-instruction log for indexers to read.
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

/// Emit a [`GeneralEvent`] (deposit/transact/merge).
#[inline(never)]
pub fn emit_general_event(kind: EventKind, event: GeneralEvent) -> ProgramResult {
    emit_encoded_event(&encode_event_instruction(kind, event))
}

/// Emit a batch address-append event. The payload is the
/// `BatchAddressAppendEvent` produced by the nullifier-tree update.
#[inline(never)]
pub fn emit_batch_address_append_event<T: BorshSerialize>(event: &T) -> ProgramResult {
    emit_encoded_event(&encode_event_instruction_with(
        EventKind::BatchAddressAppend,
        event,
    ))
}
