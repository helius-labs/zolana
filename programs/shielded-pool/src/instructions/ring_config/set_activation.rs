use crate::instructions::shared::caused_by;
use pinocchio::{AccountView, ProgramResult};
use zolana_account_checks::AccountIterator;
use zolana_interface::{error::ShieldedPoolError, instruction::SetRingActivationData};

use crate::instructions::{
    protocol_config::loader::validate_ring_creation_authority,
    ring_config::loader::load_ring_config_mut,
};

/// Governance admits a ring, or contains one it no longer trusts.
///
/// This is the counterpart to permissionless `create_ring_config`: the ring
/// registers itself, and governance decides here whether that config may
/// authorize anything. The pool is called directly, so no ring program is ever
/// in the call chain and a governance signature can never reach candidate ring
/// code.
///
/// Both flags are governance-owned. `paused` is not: it stays with the ring, so
/// a ring can protect itself without governance and governance cannot silently
/// unpause it. Deactivating a live ring strands its UTXOs, which move only
/// through ring instructions -- the deliberate containment power documented in
/// `docs/spec.md`.
pub fn process_set_ring_activation(accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    let data = *bytemuck::try_from_bytes::<SetRingActivationData>(data)
        .map_err(caused_by(ShieldedPoolError::InvalidInstructionData))?;
    let mut iter = AccountIterator::new(accounts);
    let authority = iter.next_signer("authority")?;
    let protocol_config = iter.next_account("protocol_config")?;
    let config = iter.next_mut("ring_config")?;

    validate_ring_creation_authority(protocol_config, authority)?;

    let mut current = load_ring_config_mut(config)?;
    current.activated = u8::from(data.activated != 0);
    current.ring_authority_transact_is_enabled =
        u8::from(data.ring_authority_transact_is_enabled != 0);
    Ok(())
}
