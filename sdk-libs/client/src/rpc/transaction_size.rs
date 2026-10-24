//! Transaction sizing shared with protocol operators.
use crate::{ClientError, ComputeBudgetConfig};
use solana_address::Address;
use solana_instruction::Instruction;
pub use zolana_protocol_transaction::{TransactionSize, SIGNATURE_LEN};
pub fn transaction_size(
    payer: &Address,
    instructions: &[Instruction],
    budget: ComputeBudgetConfig,
) -> Result<TransactionSize, ClientError> {
    zolana_protocol_transaction::transaction_size(payer, instructions, budget).map_err(Into::into)
}
