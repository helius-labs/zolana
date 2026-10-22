//! `create_ring_config` (tag 3): initialize the singleton ring config PDA.

use pinocchio::{AccountView, ProgramResult};
use zolana_squads_interface::{
    constants::REQUIRED_AUDITOR_KEY_COUNT, error::SquadsRingError,
    instruction::instruction_data::CreateRingConfigIxData, state::ring_config::RingConfig,
    RING_CONFIG_PDA_SEED,
};

use crate::shared::pda::{verify_pda, CreatePdaAccount};

/// `create_ring_config` (tag 3): initialize the singleton ring config PDA.
///
/// Accounts: `[creator (signer, writable, fee payer), ring_config (writable, the
/// new PDA), system_program]`. The config is created at the canonical
/// `[b"ring_config"]` PDA, sized exactly for its serialized form, and stamped
/// with the discriminator via [`RingConfig::new`].
#[inline(never)]
pub fn process_create_ring_config_ix(accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    if accounts.len() < 3 {
        return Err(SquadsRingError::InvalidInstructionData.into());
    }
    let (creator, rest) = accounts
        .split_first_mut()
        .ok_or(SquadsRingError::InvalidInstructionData)?;
    let ring_config = rest
        .first_mut()
        .ok_or(SquadsRingError::InvalidInstructionData)?;

    if !creator.is_signer() {
        return Err(SquadsRingError::MissingAuthoritySignature.into());
    }

    let ix = CreateRingConfigIxData::deserialize(data)
        .map_err(|_| SquadsRingError::InvalidInstructionData)?;

    if ix.auditor_keys.len() != REQUIRED_AUDITOR_KEY_COUNT {
        return Err(SquadsRingError::InvalidAuditorKeyCount.into());
    }

    let bump = verify_pda(ring_config.address(), &[RING_CONFIG_PDA_SEED], &crate::ID)?;

    let config = RingConfig::new(
        ix.authority,
        ix.co_signer,
        ix.max_proposal_lifetime,
        ix.auditor_keys.clone(),
        ix.merge_authorities.clone(),
    );
    let space = RingConfig::account_size(ix.auditor_keys.len(), ix.merge_authorities.len());

    CreatePdaAccount {
        fee_payer: creator,
        new_account: &mut *ring_config,
        space,
        owner: &crate::ID,
        signer_seeds: [RING_CONFIG_PDA_SEED],
        bump,
    }
    .execute()
    .map_err(|_| SquadsRingError::InvalidRingConfig)?;

    write_ring_config(ring_config, &config)
}

/// Serialize `config` and overwrite the account data in place. The account must
/// already be sized to exactly the serialized length (the create path allocates
/// it that way; the update path resizes it first).
#[inline(never)]
pub(super) fn write_ring_config(account: &mut AccountView, config: &RingConfig) -> ProgramResult {
    let bytes = config
        .serialize()
        .map_err(|_| SquadsRingError::Deserialization)?;
    let mut data = account
        .try_borrow_mut()
        .map_err(|_| SquadsRingError::InvalidRingConfig)?;
    let slot = data
        .get_mut(..bytes.len())
        .ok_or(SquadsRingError::InvalidAccountSize)?;
    slot.copy_from_slice(&bytes);
    Ok(())
}
