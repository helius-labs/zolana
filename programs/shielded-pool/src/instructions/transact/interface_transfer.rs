use pinocchio::ProgramResult;
use zolana_interface::{
    error::ShieldedPoolError, instruction::instruction_data::transact::InterfaceTransfer,
};

use crate::instructions::settlement::Settlement;

/// Applies public settlement only after the proof that authorizes it has
/// verified, so invalid proofs cannot trigger CPIs or mask verification errors.
pub(crate) fn settle_interface_transfers<E>(
    interface_transfers: impl ExactSizeIterator<Item = Result<InterfaceTransfer, E>>,
    settlements: &[Settlement<'_>],
) -> ProgramResult {
    if interface_transfers.len() != settlements.len() {
        return Err(ShieldedPoolError::InvalidSettlementAccounts.into());
    }
    for (transfer, settlement) in interface_transfers.zip(settlements.iter()) {
        let transfer = transfer.map_err(|_| ShieldedPoolError::InvalidInstructionData)?;
        if transfer.is_deposit() != settlement.is_deposit() {
            return Err(ShieldedPoolError::InvalidSettlementAccounts.into());
        }
        settlement.settle(transfer.amount())?;
    }

    Ok(())
}
