use pinocchio::{error::ProgramError, AccountView, Address};
use zolana_account_checks::AccountIterator;
use zolana_interface::error::ShieldedPoolError;

use crate::instructions::zone_config::loader::load_zone_config;

/// Validated accounts for `merge_zone`, in loader order: `tree` (writable),
/// `zone_config` (the zone's `zone_auth` PDA, signer), `payer` (signer). The
/// `zone_config` must sign and be a valid SPP-owned config: only the zone program
/// can sign for its `zone_auth` PDA, so the signature plus the owner + discriminator
/// check is the zone's authorization.
pub struct MergeZoneAccounts<'a> {
    pub tree: &'a mut AccountView,
    pub payer: &'a AccountView,
    /// The calling zone's `program_id`, read from the signed `zone_config`. Bound
    /// into the proof as the UTXO `zone_program_id`.
    pub zone_program_id: Address,
}

impl<'a> MergeZoneAccounts<'a> {
    pub fn validate_and_parse(accounts: &'a mut [AccountView]) -> Result<Self, ProgramError> {
        let mut iter = AccountIterator::new(accounts);
        let tree = iter.next_mut("tree")?;
        let zone_config = iter.next_signer("zone_config")?;
        let zone_program_id = load_zone_config(zone_config)?.program_id;
        let payer = iter.next_signer("payer")?;
        let system_program = iter.next_account("system_program")?;
        if !pinocchio_system::check_id(system_program.address()) {
            return Err(ShieldedPoolError::InvalidSystemProgram.into());
        }
        Ok(Self {
            tree,
            payer,
            zone_program_id,
        })
    }
}
