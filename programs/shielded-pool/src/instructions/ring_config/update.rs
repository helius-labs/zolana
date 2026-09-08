use crate::instructions::shared::caused_by;
use borsh::BorshDeserialize;
use pinocchio::{AccountView, ProgramResult};
use zolana_account_checks::AccountIterator;
use zolana_interface::{error::ShieldedPoolError, instruction::UpdateRingConfigData};

use crate::instructions::ring_config::loader::load_and_validate_ring_authority_mut;

pub fn process_update_ring_config(accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    let data = UpdateRingConfigData::try_from_slice(data)
        .map_err(caused_by(ShieldedPoolError::InvalidInstructionData))?;
    let mut iter = AccountIterator::new(accounts);
    let authority = iter.next_signer("authority")?;
    let config = iter.next_mut("ring_config")?;

    // `paused` is the only field the ring itself may write. Both
    // `ring_authority_transact_is_enabled` and `activated` are governance-owned,
    // because the authority-transact rail moves UTXOs with no owner signatures.
    let mut current = load_and_validate_ring_authority_mut(config, authority)?;
    current.paused = u8::from(data.paused);
    Ok(())
}
