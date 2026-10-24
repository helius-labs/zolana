use solana_address::Address;
use solana_hash::Hash;
use solana_instruction::Instruction;
use solana_keypair::Signer;
use solana_message::VersionedMessage;
use solana_transaction::versioned::VersionedTransaction;
use zolana_interface::instruction::InterfaceTransfer;
use zolana_program::instruction::TransactInterfaceTransferAccounts;

use crate::error::ClientError;

use super::compute_budget::ComputeBudgetConfig;

/// Compile `instructions` into an unsigned v1 message.
///
/// v1 takes no compute-budget instructions, which is where the ceilings in
/// `compute_budget` would otherwise go, and it has no address lookup tables.
pub fn compile_message(
    payer: &Address,
    instructions: &[Instruction],
    recent_blockhash: Hash,
    compute_budget: ComputeBudgetConfig,
) -> Result<VersionedMessage, ClientError> {
    zolana_protocol_transaction::compile_message(
        payer,
        instructions,
        recent_blockhash,
        compute_budget,
    )
    .map_err(Into::into)
}

#[cfg(feature = "solana-rpc")]
pub(crate) fn ensure_version_1(message: &VersionedMessage) -> Result<(), ClientError> {
    match message {
        VersionedMessage::V1(_) => Ok(()),
        VersionedMessage::Legacy(_) | VersionedMessage::V0(_) => {
            Err(ClientError::UnsupportedTransactionVersion)
        }
    }
}

/// Sign a compiled message, passing each signer once.
///
/// `VersionedTransaction::try_new` refuses a signer list longer than the
/// message's required signatures, where legacy partial signing tolerated a
/// repeat. A fee payer that also owns a shielded input is one account key but
/// two entries in the caller's list (payer and owner signer), so the
/// duplicates are dropped here rather than at every call site.
pub fn sign_transaction(
    message: VersionedMessage,
    signers: &[&dyn Signer],
) -> Result<VersionedTransaction, ClientError> {
    zolana_protocol_transaction::sign_transaction(message, signers).map_err(Into::into)
}

#[must_use]
pub struct SettlementAccountValidation<'a> {
    pub transfers: &'a [InterfaceTransfer],
    pub accounts: &'a [TransactInterfaceTransferAccounts],
}

impl SettlementAccountValidation<'_> {
    pub fn validate(self) -> Result<(), ClientError> {
        if self.transfers.len() != self.accounts.len() {
            return Err(ClientError::SettlementTransferCountMismatch {
                interface_transfers: self.transfers.len(),
                account_groups: self.accounts.len(),
            });
        }
        for (index, (transfer, accounts)) in self.transfers.iter().zip(self.accounts).enumerate() {
            if !matches!(
                (transfer, accounts),
                (
                    InterfaceTransfer::SolDeposit { .. } | InterfaceTransfer::SolWithdrawal { .. },
                    TransactInterfaceTransferAccounts::Sol(_)
                ) | (
                    InterfaceTransfer::SplDeposit { .. },
                    TransactInterfaceTransferAccounts::SplDeposit(_)
                ) | (
                    InterfaceTransfer::SplWithdrawal { .. },
                    TransactInterfaceTransferAccounts::SplWithdrawal(_)
                )
            ) {
                return Err(ClientError::SettlementTransferTypeMismatch { index });
            }
        }
        Ok(())
    }
}
