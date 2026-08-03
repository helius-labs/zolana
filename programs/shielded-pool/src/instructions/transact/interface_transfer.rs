use pinocchio::ProgramResult;
use zolana_interface::{
    error::ShieldedPoolError,
    instruction::instruction_data::transact::{
        InterfaceTransfer, ResolvedInterfaceTransfer, TransactIxDataRef,
    },
};

use crate::instructions::settlement::Settlement;

/// Applies public settlement only after the proof that authorizes it has
/// verified, so invalid proofs cannot trigger CPIs or mask verification errors.
pub(crate) fn settle_interface_transfers(
    interface_transfers: &[InterfaceTransfer],
    settlements: &[Settlement<'_>],
) -> ProgramResult {
    for (transfer, settlement) in interface_transfers.iter().zip(settlements.iter()) {
        if transfer.is_deposit() != settlement.is_deposit() {
            return Err(ShieldedPoolError::InvalidSettlementAccounts.into());
        }
        settlement.settle(transfer.amount())?;
    }

    Ok(())
}

pub(crate) fn resolve_interface_transfers(
    ix: &TransactIxDataRef<'_>,
    settlements: &[Settlement<'_>],
) -> Vec<ResolvedInterfaceTransfer> {
    let mut resolved = Vec::with_capacity(ix.interface_transfers.len());
    for (transfer, settlement) in ix.interface_transfers.iter().zip(settlements.iter()) {
        let amount = transfer.amount();
        let resolved_transfer = match settlement {
            Settlement::SolDeposit(sol) => ResolvedInterfaceTransfer::SolDeposit {
                amount,
                recipient: sol.recipient_account.address().to_bytes(),
            },
            Settlement::SolWithdrawal(sol) => ResolvedInterfaceTransfer::SolWithdrawal {
                amount,
                recipient: sol.recipient_account.address().to_bytes(),
            },
            Settlement::SplDeposit(spl) => ResolvedInterfaceTransfer::SplDeposit {
                amount,
                user_token_account: spl.user_token_account.address().to_bytes(),
                spl_interface: spl.spl_interface_account.address().to_bytes(),
            },
            Settlement::SplWithdrawal(spl) => ResolvedInterfaceTransfer::SplWithdrawal {
                amount,
                user_token_account: spl.user_token_account.address().to_bytes(),
                spl_interface: spl.spl_interface_account.address().to_bytes(),
            },
        };
        resolved.push(resolved_transfer);
    }
    resolved
}
