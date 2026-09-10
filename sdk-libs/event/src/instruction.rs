use solana_pubkey::Pubkey;

/// One instruction of a confirmed transaction with its account list resolved to
/// addresses. `stack_height` is `1` for a top-level instruction and grows by one
/// per CPI level; event discovery walks it to find an event's parent, so an
/// adapter must reject transaction metadata that lacks it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParsedInstruction {
    pub program_id: Pubkey,
    pub accounts: Vec<Pubkey>,
    pub data: Vec<u8>,
    pub stack_height: u32,
}

impl ParsedInstruction {
    pub fn new(
        program_id: Pubkey,
        accounts: Vec<Pubkey>,
        data: Vec<u8>,
        stack_height: u32,
    ) -> Self {
        Self {
            program_id,
            accounts,
            data,
            stack_height,
        }
    }
}

/// A top-level instruction with the inner instructions it caused, in execution
/// order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InstructionGroup {
    pub outer: ParsedInstruction,
    pub inner: Vec<ParsedInstruction>,
}
