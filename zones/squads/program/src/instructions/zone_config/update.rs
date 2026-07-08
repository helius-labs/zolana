//! `update_zone_config` (tag 4): overwrite the zone config's mutable fields.

use pinocchio::{
    sysvars::{rent::Rent, Sysvar},
    AccountView, Address, ProgramResult, Resize,
};
use zolana_squads_interface::{
    constants::REQUIRED_AUDITOR_KEY_COUNT, error::SquadsZoneError,
    instruction::instruction_data::UpdateZoneConfigIxData, state::zone_config::ZoneConfig,
};

use super::{create::write_zone_config, loader::load_zone_config};

/// `update_zone_config` (tag 4): overwrite the zone config's mutable fields.
///
/// Accounts: `[authority (signer), zone_config (writable)]`. Only the recorded
/// `authority` may update; the default (zero) authority freezes the config.
#[inline(never)]
pub fn process_update_zone_config_ix(accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    if accounts.len() < 2 {
        return Err(SquadsZoneError::InvalidInstructionData.into());
    }
    let (authority, rest) = accounts
        .split_first_mut()
        .ok_or(SquadsZoneError::InvalidInstructionData)?;
    let zone_config = rest
        .first_mut()
        .ok_or(SquadsZoneError::InvalidInstructionData)?;

    if !authority.is_signer() {
        return Err(SquadsZoneError::MissingAuthoritySignature.into());
    }

    // Owner + discriminator are validated by the loader.
    let current = load_zone_config(zone_config)?;

    // A zeroed authority means the config was frozen; reject before any
    // authority comparison so a zero-key signer cannot masquerade as it.
    if current.authority == Address::default() {
        return Err(SquadsZoneError::ConfigFrozen.into());
    }
    if authority.address() != &current.authority {
        return Err(SquadsZoneError::AuthorityMismatch.into());
    }
    // `current` is an owned value, so there is no outstanding borrow to drop.

    let ix = UpdateZoneConfigIxData::deserialize(data)
        .map_err(|_| SquadsZoneError::InvalidInstructionData)?;

    if ix.auditor_keys.len() != REQUIRED_AUDITOR_KEY_COUNT {
        return Err(SquadsZoneError::InvalidAuditorKeyCount.into());
    }

    let config = ZoneConfig::new(
        ix.authority,
        ix.co_signer,
        ix.max_proposal_lifetime,
        ix.auditor_keys.clone(),
        ix.merge_authorities.clone(),
    );
    let new_size = ZoneConfig::account_size(ix.auditor_keys.len(), ix.merge_authorities.len());

    if new_size != zone_config.data_len() {
        // The merge-authority count changed, so the account must be resized to
        // the new exact serialized length. The account stays program-owned, so
        // a shrink keeps it (over-funded) rent-exempt; a grow must already be
        // covered by the current balance, because this instruction's account
        // set has no fee payer or system program to fund a rent top-up.
        if new_size > zone_config.data_len() {
            let required = Rent::get()?.try_minimum_balance(new_size)?;
            if zone_config.lamports() < required {
                return Err(SquadsZoneError::InvalidAccountSize.into());
            }
        }
        zone_config
            .resize(new_size)
            .map_err(|_| SquadsZoneError::InvalidAccountSize)?;
    }

    write_zone_config(zone_config, &config)
}
