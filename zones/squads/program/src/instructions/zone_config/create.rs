//! `create_zone_config` (tag 3): initialize the singleton zone config PDA.

use pinocchio::{AccountView, ProgramResult};
use zolana_squads_interface::{
    constants::REQUIRED_AUDITOR_KEY_COUNT, error::SquadsZoneError,
    instruction::instruction_data::CreateZoneConfigIxData, state::zone_config::ZoneConfig,
    ZONE_CONFIG_PDA_SEED,
};

use crate::shared::pda::{verify_pda, CreatePdaAccount};

/// `create_zone_config` (tag 3): initialize the singleton zone config PDA.
///
/// Accounts: `[creator (signer, writable, fee payer), zone_config (writable, the
/// new PDA), system_program]`. The config is created at the canonical
/// `[b"zone_config"]` PDA, sized exactly for its serialized form, and stamped
/// with the discriminator via [`ZoneConfig::new`].
#[inline(never)]
pub fn process_create_zone_config_ix(accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    if accounts.len() < 3 {
        return Err(SquadsZoneError::InvalidInstructionData.into());
    }
    let (creator, rest) = accounts
        .split_first_mut()
        .ok_or(SquadsZoneError::InvalidInstructionData)?;
    let zone_config = rest
        .first_mut()
        .ok_or(SquadsZoneError::InvalidInstructionData)?;

    if !creator.is_signer() {
        return Err(SquadsZoneError::MissingAuthoritySignature.into());
    }

    let ix = CreateZoneConfigIxData::deserialize(data)
        .map_err(|_| SquadsZoneError::InvalidInstructionData)?;

    if ix.auditor_keys.len() != REQUIRED_AUDITOR_KEY_COUNT {
        return Err(SquadsZoneError::InvalidAuditorKeyCount.into());
    }

    let bump = verify_pda(zone_config.address(), &[ZONE_CONFIG_PDA_SEED], &crate::ID)?;

    let config = ZoneConfig::new(
        ix.authority,
        ix.co_signer,
        ix.max_proposal_lifetime,
        ix.auditor_keys.clone(),
        ix.merge_authorities.clone(),
    );
    let space = ZoneConfig::account_size(ix.auditor_keys.len(), ix.merge_authorities.len());

    CreatePdaAccount {
        fee_payer: creator,
        new_account: &mut *zone_config,
        space,
        owner: &crate::ID,
        signer_seeds: [ZONE_CONFIG_PDA_SEED],
        bump,
    }
    .execute()
    .map_err(|_| SquadsZoneError::InvalidZoneConfig)?;

    write_zone_config(zone_config, &config)
}

/// Serialize `config` and overwrite the account data in place. The account must
/// already be sized to exactly the serialized length (the create path allocates
/// it that way; the update path resizes it first).
#[inline(never)]
pub(super) fn write_zone_config(account: &mut AccountView, config: &ZoneConfig) -> ProgramResult {
    let bytes = config
        .serialize()
        .map_err(|_| SquadsZoneError::Deserialization)?;
    let mut data = account
        .try_borrow_mut()
        .map_err(|_| SquadsZoneError::InvalidZoneConfig)?;
    let slot = data
        .get_mut(..bytes.len())
        .ok_or(SquadsZoneError::InvalidAccountSize)?;
    slot.copy_from_slice(&bytes);
    Ok(())
}
