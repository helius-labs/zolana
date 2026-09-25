use solana_address::Address;
use solana_hash::Hash;
use solana_instruction::Instruction;
use solana_keypair::Signer;
use solana_message::{v1, VersionedMessage};
use solana_pubkey::Pubkey;
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
    v1::Message::try_compile_with_config(
        payer,
        instructions,
        recent_blockhash,
        compute_budget.transaction_config(),
    )
    .map(VersionedMessage::V1)
    .map_err(|error| ClientError::TransactionCompile(error.to_string()))
}

/// Sign a compiled message, passing each signer once.
///
/// `VersionedTransaction::try_new` refuses a signer list longer than the
/// message's required signatures, where legacy partial signing tolerated a
/// repeat. A fee payer that also owns a shielded input is one account key but
/// two entries in the caller's list, so the duplicates are dropped here rather
/// than at every call site.
pub fn sign_transaction(
    message: VersionedMessage,
    signers: &[&dyn Signer],
) -> Result<VersionedTransaction, ClientError> {
    let mut unique: Vec<(Pubkey, &dyn Signer)> = Vec::with_capacity(signers.len());
    for signer in signers {
        let pubkey = signer
            .try_pubkey()
            .map_err(|error| ClientError::SolanaTransactionSigning(error.to_string()))?;
        if unique.iter().any(|(kept, _)| *kept == pubkey) {
            continue;
        }
        unique.push((pubkey, *signer));
    }
    let unique = unique
        .into_iter()
        .map(|(_, signer)| signer)
        .collect::<Vec<_>>();
    VersionedTransaction::try_new(message, &unique)
        .map_err(|error| ClientError::SolanaTransactionSigning(error.to_string()))
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
