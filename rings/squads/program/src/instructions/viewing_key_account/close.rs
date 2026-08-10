use pinocchio::{AccountView, ProgramResult};
use zolana_squads_interface::{
    error::SquadsRingError, event::ViewingKeyAccountClosedEvent, types::Address,
};

use super::loader::load_viewing_key_account;
use crate::instructions::ring_config::loader::load_ring_config;
use crate::shared::{
    close::close_account,
    event::{emit_viewing_key_account_closed_event, validate_ring_program},
    owner::is_owner_identity,
};

/// `close_viewing_key_account` (tag 8): close a viewing key account and refund
/// rent to the supplied rent recipient.
///
/// Accounts: `[authority (signer), viewing_key_account (writable),
/// rent_recipient (writable), ring_config (readonly), program (self-CPI event
/// target)]`.
///
/// The authority is the account's own owner or the ring co-signer. A keypair
/// owner is stored as a hash of its address and can never satisfy the owner
/// test, so without the co-signer such an account could never be closed.
#[inline(never)]
pub fn process_close_viewing_key_account_ix(
    accounts: &mut [AccountView],
    _data: &[u8],
) -> ProgramResult {
    let [authority, viewing_key_account, rent_recipient, ring_config, program] = accounts else {
        return Err(SquadsRingError::InvalidInstructionData.into());
    };

    if !authority.is_signer() {
        return Err(SquadsRingError::MissingOwnerSignature.into());
    }
    validate_ring_program(program)?;

    let current = load_viewing_key_account(viewing_key_account)?;
    let ring = load_ring_config(ring_config)?;
    if authority.address() != &ring.co_signer
        && !is_owner_identity(authority, current.owner.to_bytes())?
    {
        return Err(SquadsRingError::OwnerMismatch.into());
    }

    // The close destroys the shared viewing key, its commitment, the nullifier
    // pubkey and every recovery/auditor ciphertext, while the UTXO ciphertexts
    // they decrypt stay on chain. Record the state before it is gone.
    emit_viewing_key_account_closed_event(&ViewingKeyAccountClosedEvent {
        account: Address::new_from_array(viewing_key_account.address().to_bytes()),
        state: current,
    })?;

    close_account(
        viewing_key_account,
        rent_recipient,
        SquadsRingError::InvalidViewingKeyAccount,
    )
}
