use pinocchio::{
    sysvars::{rent::Rent, Sysvar},
    AccountView, Address, ProgramResult, Resize,
};
use zolana_squads_interface::{
    constants::REQUIRED_AUDITOR_KEY_COUNT, error::SquadsRingError,
    instruction::instruction_data::UpdateRingConfigIxData, state::ring_config::SquadsRingConfig,
};

use super::{create::write_ring_config, loader::load_ring_config};

/// `update_ring_config` (tag 4): overwrite the ring config's mutable fields.
///
/// Accounts: `[authority (signer), ring_config (writable)]`. Only the recorded
/// `authority` may update. The default (zero) authority freezes the config.
#[inline(never)]
pub fn process_update_ring_config_ix(accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    if accounts.len() < 2 {
        return Err(SquadsRingError::InvalidInstructionData.into());
    }
    let (authority, rest) = accounts
        .split_first_mut()
        .ok_or(SquadsRingError::InvalidInstructionData)?;
    let ring_config = rest
        .first_mut()
        .ok_or(SquadsRingError::InvalidInstructionData)?;

    if !authority.is_signer() {
        return Err(SquadsRingError::MissingAuthoritySignature.into());
    }

    let current = load_ring_config(ring_config)?;

    // A zeroed authority means the config was frozen. Reject before any
    // authority comparison so a zero-key signer cannot masquerade as it.
    if current.authority == Address::default() {
        return Err(SquadsRingError::ConfigFrozen.into());
    }
    if authority.address() != &current.authority {
        return Err(SquadsRingError::AuthorityMismatch.into());
    }

    let ix = UpdateRingConfigIxData::deserialize(data)
        .map_err(|_| SquadsRingError::InvalidInstructionData)?;

    if ix.auditor_keys.len() != REQUIRED_AUDITOR_KEY_COUNT {
        return Err(SquadsRingError::InvalidAuditorKeyCount.into());
    }

    let config = SquadsRingConfig::new(
        ix.authority,
        ix.co_signer,
        ix.max_proposal_lifetime,
        ix.auditor_keys.clone(),
        ix.merge_authorities.clone(),
    );
    let new_size =
        SquadsRingConfig::account_size(ix.auditor_keys.len(), ix.merge_authorities.len());

    if new_size != ring_config.data_len() {
        // The account stays program-owned, so a shrink keeps it rent-exempt. A
        // grow must already be covered by the current balance, because this
        // instruction's account set has no fee payer or system program to fund
        // a rent top-up.
        if new_size > ring_config.data_len() {
            let required = Rent::get()?.try_minimum_balance(new_size)?;
            if ring_config.lamports() < required {
                return Err(SquadsRingError::InvalidAccountSize.into());
            }
        }
        ring_config
            .resize(new_size)
            .map_err(|_| SquadsRingError::InvalidAccountSize)?;
    }

    write_ring_config(ring_config, &config)
}
