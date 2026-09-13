use pinocchio::ProgramResult;
use zolana_interface::{
    error::ShieldedPoolError, instruction::instruction_data::transact::InterfaceTransfer,
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
