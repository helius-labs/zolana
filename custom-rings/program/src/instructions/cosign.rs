use custom_ring_interface::{COSIGN_DEPOSITS, COSIGN_TRANSFERS, COSIGN_WITHDRAWALS};
use pinocchio::{error::ProgramError, AccountView, Address};

use crate::{
    error::CustomRingError,
    instructions::{loader::load_cosigner, public_legs::PublicLegs},
};

/// Classifies an operation for scoped approval using its public settlement amounts.
pub(crate) struct CoSignerRequirement<'a> {
    pub classes: u8,
    pub legs: PublicLegs<'a>,
}

impl<'a> CoSignerRequirement<'a> {
    pub const TRANSFER: Self = Self {
        classes: COSIGN_TRANSFERS,
        legs: PublicLegs::NONE,
    };

    /// A transact is a transfer, each public leg adds its class.
    pub fn transact(legs: PublicLegs<'a>) -> Self {
        let mut classes = COSIGN_TRANSFERS;
        if legs.has_deposits() {
            classes |= COSIGN_DEPOSITS;
        }
        if legs.withdrawals().next().is_some() {
            classes |= COSIGN_WITHDRAWALS;
        }
        Self { classes, legs }
    }

    pub fn deposit(legs: PublicLegs<'a>) -> Self {
        Self {
            classes: COSIGN_DEPOSITS,
            legs,
        }
    }
}

/// No account at the canonical address demands nothing.
pub(crate) fn require_cosigner(
    program_id: &Address,
    cosigner_account: &AccountView,
    signer: &AccountView,
    demand: &CoSignerRequirement,
) -> Result<(), ProgramError> {
    // 1. Resolve the canonical optional control account.
    let Some(cosigner) = load_cosigner(program_id, cosigner_account)? else {
        return Ok(());
    };
    // 2. Combine operation scope with aggregate withdrawal thresholds per mint.
    let mut in_scope = cosigner.scope & demand.classes & (COSIGN_TRANSFERS | COSIGN_DEPOSITS) != 0;
    if !in_scope && cosigner.scope & demand.classes & COSIGN_WITHDRAWALS != 0 {
        for withdrawal in demand.legs.withdrawals() {
            let (mint, sum) = withdrawal?;
            if cosigner.threshold(mint).is_none_or(|limit| sum > limit) {
                in_scope = true;
                break;
            }
        }
    }
    if !in_scope {
        return Ok(());
    }
    // 3. Require the configured signer only when an approval condition applies.
    check_signature(signer, &cosigner.signer)
}

/// The approval bit demands the co-signer whatever its scope.
pub(crate) fn require_approval(
    program_id: &Address,
    cosigner_account: &AccountView,
    signer: &AccountView,
) -> Result<(), ProgramError> {
    let cosigner = load_cosigner(program_id, cosigner_account)?
        .ok_or(CustomRingError::ApprovalWithoutCoSigner)?;
    check_signature(signer, &cosigner.signer)
}

fn check_signature(signer: &AccountView, cosigner: &Address) -> Result<(), ProgramError> {
    if !signer.is_signer() {
        return Err(CustomRingError::MissingCoSigner.into());
    }
    if signer.address() != cosigner {
        return Err(CustomRingError::UnauthorizedCoSigner.into());
    }
    Ok(())
}
