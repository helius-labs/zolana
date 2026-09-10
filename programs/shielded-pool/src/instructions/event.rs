use borsh::BorshSerialize;
use pinocchio::{cpi::invoke, instruction::InstructionView, AccountView, ProgramResult};
use zolana_interface::event::{encode_event_instruction, EventKind};

/// Emit an event by self-CPI: the program re-invokes itself with
/// `[EMIT_EVENT, kind, borsh(event)]` as instruction data and no accounts, so the
/// event is recorded in the transaction's inner-instruction log for indexers to
/// read. `event` must be the body type [`EventKind`] documents for `kind`.
#[inline(never)]
pub fn emit_event<T: BorshSerialize>(kind: EventKind, event: &T) -> ProgramResult {
    let data = encode_event_instruction(kind, event);
    let instruction = InstructionView {
        program_id: &crate::ID,
        accounts: &[],
        data: &data,
    };
    let accounts: [&AccountView; 0] = [];
    invoke(&instruction, &accounts)
}
