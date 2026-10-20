use custom_ring_interface::{CoSignScope, CoSigner, CustomRingError};
use pinocchio::{error::ProgramError, AccountView, Address};

use crate::instructions::{loader::load_optional, public_legs::PublicLegs};

/// The co-signer the configured scope demands for `classes`, withdrawals per
/// mint above their threshold, `None` without a co-signer account.
pub(crate) fn demanded_cosigner(
    program_id: &Address,
    cosigner_pda: &AccountView,
    classes: CoSignScope,
    legs: &PublicLegs<'_>,
) -> Result<Option<Address>, ProgramError> {
    let Some(cosigner) = load_optional::<CoSigner, 1>(program_id, cosigner_pda, &[CoSigner::SEED])?
    else {
        return Ok(None);
    };
    let shared = |class| cosigner.scope().contains(class) && classes.contains(class);
    let mut in_scope = shared(CoSignScope::TRANSFERS) || shared(CoSignScope::DEPOSITS);
    if !in_scope && shared(CoSignScope::WITHDRAWALS) {
        for withdrawal in legs.withdrawals() {
            let (mint, sum) = withdrawal?;
            if cosigner.threshold(mint).is_none_or(|limit| sum > limit) {
                in_scope = true;
                break;
            }
        }
    }
    Ok(in_scope.then_some(cosigner.signer))
}

/// The approval bit demands the co-signer whatever its scope.
pub(crate) fn approval_cosigner(
    program_id: &Address,
    cosigner_pda: &AccountView,
) -> Result<Address, ProgramError> {
    Ok(
        load_optional::<CoSigner, 1>(program_id, cosigner_pda, &[CoSigner::SEED])?
            .ok_or(CustomRingError::ApprovalWithoutCoSigner)?
            .signer,
    )
}

/// The configured co-signer an anonymous spend publishes, the zero address without one.
pub(crate) fn configured_cosigner(
    program_id: &Address,
    cosigner_pda: &AccountView,
) -> Result<Address, ProgramError> {
    Ok(
        load_optional::<CoSigner, 1>(program_id, cosigner_pda, &[CoSigner::SEED])?
            .map_or(Address::from([0u8; 32]), |cosigner| cosigner.signer),
    )
}
