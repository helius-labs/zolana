//! Measuring a transaction against the v1 limits.
//!
//! v1 has two ceilings, and a transaction has to clear both: 4,096 wire bytes,
//! and 64 account addresses. The byte ceiling is the one the shielded pool was
//! built around; the address ceiling is the one that creeps up unnoticed,
//! because a wide spend adds one nullifier PDA per input.

use solana_address::Address;
use solana_hash::Hash;
use solana_instruction::Instruction;
use solana_message::v1;

use crate::{error::ClientError, ComputeBudgetConfig};

/// The one-byte version prefix a v1 transaction carries ahead of its message.
const VERSION_PREFIX_LEN: usize = 1;
pub const SIGNATURE_LEN: usize = 64;

/// What a compiled transaction costs against each v1 ceiling.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TransactionSize {
    pub bytes: usize,
    pub addresses: usize,
}

impl TransactionSize {
    /// Whether the transaction clears both ceilings. Neither alone is enough.
    pub fn fits(&self) -> bool {
        self.bytes <= v1::MAX_TRANSACTION_SIZE && self.addresses <= usize::from(v1::MAX_ADDRESSES)
    }
}

/// Measure `instructions` as the v1 transaction they would be sent as.
///
/// Includes the configured header fields and every signature required by the
/// compiled message. Use the same budget as the sender.
pub fn transaction_size(
    payer: &Address,
    instructions: &[Instruction],
    compute_budget: ComputeBudgetConfig,
) -> Result<TransactionSize, ClientError> {
    let message = v1::Message::try_compile_with_config(
        payer,
        instructions,
        Hash::default(),
        compute_budget.transaction_config(),
    )
    .map_err(|error| ClientError::TransactionCompile(error.to_string()))?;
    let signatures = usize::from(message.header.num_required_signatures);
    let bytes = signatures
        .checked_mul(SIGNATURE_LEN)
        .and_then(|signatures| signatures.checked_add(VERSION_PREFIX_LEN))
        .and_then(|overhead| overhead.checked_add(message.size()))
        .ok_or_else(|| ClientError::TransactionCompile("transaction size overflow".to_owned()))?;
    Ok(TransactionSize {
        bytes,
        addresses: message.account_keys.len(),
    })
}
