use custom_ring_interface::CoSignScope;
use pinocchio::{error::ProgramError, AccountView, Address};

use crate::{
    error::CustomRingError,
    instructions::{loader::load_cosigner, public_legs::PublicLegs},
};

pub(crate) struct CoSignerRequirement<'a> {
    pub classes: CoSignScope,
    pub legs: PublicLegs<'a>,
}

impl<'a> CoSignerRequirement<'a> {
    pub const TRANSFER: Self = Self {
        classes: CoSignScope::TRANSFERS,
        legs: PublicLegs::NONE,
    };

    /// A transact is a transfer, each public leg adds its class.
    pub fn transact(legs: PublicLegs<'a>) -> Self {
        let mut classes = CoSignScope::TRANSFERS;
        if legs.has_deposits() {
            classes = classes | CoSignScope::DEPOSITS;
        }
        if legs.withdrawals().next().is_some() {
            classes = classes | CoSignScope::WITHDRAWALS;
        }
        Self { classes, legs }
    }

    pub fn deposit(legs: PublicLegs<'a>) -> Self {
        Self {
            classes: CoSignScope::DEPOSITS,
            legs,
        }
    }

    /// No account at the canonical address demands nothing.
    pub fn demanded_signer(
        &self,
        program_id: &Address,
        cosigner_account: &AccountView,
    ) -> Result<Option<Address>, ProgramError> {
        let Some(cosigner) = load_cosigner(program_id, cosigner_account)? else {
            return Ok(None);
        };
        let scope = cosigner.scope();
        let shared = |class| scope.contains(class) && self.classes.contains(class);
        let mut in_scope = shared(CoSignScope::TRANSFERS) || shared(CoSignScope::DEPOSITS);
        if !in_scope && shared(CoSignScope::WITHDRAWALS) {
            for withdrawal in self.legs.withdrawals() {
                let (mint, sum) = withdrawal?;
                if cosigner.threshold(mint).is_none_or(|limit| sum > limit) {
                    in_scope = true;
                    break;
                }
            }
        }
        Ok(in_scope.then_some(cosigner.signer))
    }
}

/// The approval bit demands the co-signer whatever its scope.
pub(crate) fn approval_signer(
    program_id: &Address,
    cosigner_account: &AccountView,
) -> Result<Address, ProgramError> {
    Ok(load_cosigner(program_id, cosigner_account)?
        .ok_or(CustomRingError::ApprovalWithoutCoSigner)?
        .signer)
}
