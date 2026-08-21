use zolana_interface::instruction::{InterfaceTransfer, TransactInterfaceTransferAccounts};

use crate::ClientError;

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
