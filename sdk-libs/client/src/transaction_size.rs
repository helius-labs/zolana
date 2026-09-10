use solana_address::Address;
use solana_compute_budget_interface::ComputeBudgetInstruction;
use solana_hash::Hash;
use solana_instruction::Instruction;
use solana_message::v1;

use crate::error::ClientError;

pub const V1_VERSION_PREFIX_LEN: usize = 1;
pub const SIGNATURE_LEN: usize = 64;
pub const LEGACY_PACKET_DATA_SIZE: usize = 1232;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct V1TransactionSize {
    pub bytes: usize,
    pub addresses: usize,
}

impl V1TransactionSize {
    pub fn fits(&self) -> bool {
        self.bytes <= v1::MAX_TRANSACTION_SIZE && self.addresses <= usize::from(v1::MAX_ADDRESSES)
    }

    pub fn spare_bytes(&self) -> usize {
        v1::MAX_TRANSACTION_SIZE.saturating_sub(self.bytes)
    }
}

pub fn v1_transaction_size(
    payer: &Address,
    instructions: &[Instruction],
    signatures: usize,
) -> Result<V1TransactionSize, ClientError> {
    let message = v1::Message::try_compile(payer, instructions, Hash::default())
        .map_err(|error| ClientError::TransactionCompile(error.to_string()))?;
    let bytes = V1_VERSION_PREFIX_LEN
        .checked_add(message.size())
        .and_then(|bytes| bytes.checked_add(signatures.checked_mul(SIGNATURE_LEN)?))
        .ok_or_else(|| ClientError::TransactionCompile("transaction size overflow".to_owned()))?;
    Ok(V1TransactionSize {
        bytes,
        addresses: message.account_keys.len(),
    })
}

pub fn compute_unit_limit_instruction(limit: u32) -> Instruction {
    ComputeBudgetInstruction::set_compute_unit_limit(limit)
}
