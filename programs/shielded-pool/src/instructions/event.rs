use pinocchio::{cpi::invoke, instruction::InstructionView, AccountView, ProgramResult};
use zolana_interface::event::{encode_event_instruction, EventKind, GeneralEvent};

/// Emit a `GeneralEvent` by self-CPI: the program re-invokes itself with the
/// encoded event as instruction data and no accounts, so the event is recorded
/// in the transaction's inner-instruction log for indexers to read.
#[inline(never)]
pub fn emit_general_event(kind: EventKind, event: GeneralEvent) -> ProgramResult {
    let data = encode_event_instruction(kind, event);
    let instruction = InstructionView {
        program_id: &crate::ID,
        accounts: &[],
        data: &data,
    };
    let accounts: [&AccountView; 0] = [];
    invoke(&instruction, &accounts)
}
