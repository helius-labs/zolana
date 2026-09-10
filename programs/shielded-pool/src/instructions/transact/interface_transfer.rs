use pinocchio::{error::ProgramError, ProgramResult};
use zolana_interface::instruction::instruction_data::transact::InterfaceTransfer;

use crate::instructions::settlement::Settlement;

/// Applies public settlement only after the proof that authorizes it has
/// verified, so invalid proofs cannot trigger CPIs or mask verification errors.
pub(crate) fn settle_interface_transfers<'a>(
    settlements: impl Iterator<Item = Result<(InterfaceTransfer, Settlement<'a>), ProgramError>>,
) -> ProgramResult {
    for settlement in settlements {
        let (transfer, settlement) = settlement?;
        settlement.settle(transfer.amount())?;
    }
    Ok(())
}
