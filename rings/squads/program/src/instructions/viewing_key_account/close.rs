use pinocchio::{AccountView, ProgramResult};
use zolana_squads_interface::{
    error::SquadsZoneError, event::ViewingKeyAccountClosedEvent, types::Address,
};

use super::loader::load_viewing_key_account;
use crate::instructions::zone_config::loader::load_zone_config;
use crate::shared::{
    close::close_account,
    event::{emit_viewing_key_account_closed_event, validate_zone_program},
    owner::is_owner_identity,
};

/// `close_viewing_key_account` (tag 8): close a viewing key account and refund
/// rent to the supplied rent recipient.
///
/// Accounts: `[authority (signer), viewing_key_account (writable),
/// rent_recipient (writable), zone_config (readonly), program (self-CPI event
/// target)]`.
///
/// The authority is the account's own owner or the zone co-signer. A keypair
/// owner is stored as a hash of its address and can never satisfy the owner
/// test, so without the co-signer such an account could never be closed.
#[inline(never)]
pub fn process_close_viewing_key_account_ix(
    accounts: &mut [AccountView],
    _data: &[u8],
) -> ProgramResult {
    let [authority, viewing_key_account, rent_recipient, zone_config, program] = accounts else {
        return Err(SquadsZoneError::InvalidInstructionData.into());
    };

    if !authority.is_signer() {
        return Err(SquadsZoneError::MissingOwnerSignature.into());
    }
    validate_zone_program(program)?;

    let current = load_viewing_key_account(viewing_key_account)?;
    let zone = load_zone_config(zone_config)?;
    if authority.address() != &zone.co_signer
        && !is_owner_identity(authority, current.owner.to_bytes())?
    {
        return Err(SquadsZoneError::OwnerMismatch.into());
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
        SquadsZoneError::InvalidViewingKeyAccount,
    )
}
