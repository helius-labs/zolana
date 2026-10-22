//! `full_withdrawal` (tag 10): the permissionless escape-hatch exit.

use pinocchio::{AccountView, ProgramResult};
use zolana_interface::instruction::tag::RING_TRANSACT;
use zolana_squads_interface::{
    error::SquadsRingError, instruction::instruction_data::FullWithdrawalIxData,
};

use crate::shared::{
    cpi::forward_to_spp,
    spp_transact::{SppSettlementRail, SppTransact},
};

/// `full_withdrawal` (tag 10): exit without the co-signer or backend.
///
/// Accounts: exactly the SPP `ring_transact` account list, forwarded unchanged.
///
/// There is no ring proof: the forwarded Ed25519 SPP proof authorizes the exit (the
/// owner's signature over the private/external transaction message digest), so a blocked account can still
/// leave. The payload publishes one change output on the Ed25519 rail.
#[inline(never)]
pub fn process_full_withdrawal_ix(accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    let ix = decode(data)?;
    let spp = SppTransact::parse(&ix.spp)?;
    if spp.is_transfer() {
        return Err(SquadsRingError::InvalidInstructionData.into());
    }
    SppSettlementRail::Ed25519.check_circuit(&ix.spp.circuit)?;

    let payer = accounts
        .first()
        .ok_or(SquadsRingError::InvalidInstructionData)?;
    if !payer.is_signer() {
        return Err(SquadsRingError::MissingAuthoritySignature.into());
    }

    let mut instruction_data = Vec::with_capacity(1 + data.len());
    instruction_data.push(RING_TRANSACT);
    instruction_data.extend_from_slice(data);
    forward_to_spp(accounts, &instruction_data)
}

#[inline(never)]
fn decode(data: &[u8]) -> Result<Box<FullWithdrawalIxData>, SquadsRingError> {
    FullWithdrawalIxData::deserialize(data)
        .map(Box::new)
        .map_err(|_| SquadsRingError::InvalidInstructionData)
}
