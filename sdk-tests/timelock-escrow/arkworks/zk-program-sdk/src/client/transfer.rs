use solana_address::Address;
use zolana_transaction::{
    instructions::transact::{PublicTransferRequest, SettlementTarget, SettlementTransfer},
    SOL_MINT,
};

use super::transaction::SppTransactionBuilder;
use crate::{conversion::FromCircuit, program::PublicTransfer, RelationError};

impl From<SettlementTransfer> for PublicTransfer {
    fn from(transfer: SettlementTransfer) -> Self {
        match transfer {
            SettlementTransfer::Sol {
                is_deposit,
                amount,
                user_sol_account,
            } => Self {
                mint: SOL_MINT,
                is_deposit,
                amount,
                account: user_sol_account,
            },
            SettlementTransfer::Spl {
                mint,
                is_deposit,
                amount,
                user_spl_token,
            } => Self {
                mint,
                is_deposit,
                amount,
                account: user_spl_token,
            },
        }
    }
}

impl SppTransactionBuilder<'_> {
    pub(super) fn public_transfers(&self) -> Result<Vec<PublicTransferRequest>, RelationError> {
        self.checked
            .public_transfers
            .iter()
            .enumerate()
            .map(|(slot, transfer)| {
                let problem = |problem| RelationError::Slot {
                    kind: "public transfer",
                    slot,
                    problem,
                };
                let asset = self
                    .mint(&transfer.asset)?
                    .ok_or(problem("has an asset no input names"))?;
                let amount = u64::from_circuit(&transfer.amount)
                    .map_err(|_| problem("has an amount that does not fit in u64"))?;
                let account = Address::from_circuit(&transfer.account)?;
                let target = if asset.asset == SOL_MINT {
                    SettlementTarget::Sol {
                        user_sol_account: account,
                    }
                } else {
                    SettlementTarget::Spl {
                        user_spl_token: account,
                    }
                };
                Ok(PublicTransferRequest {
                    asset,
                    is_deposit: transfer.is_deposit,
                    amount,
                    target,
                })
            })
            .collect()
    }
}
