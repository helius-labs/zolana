use pinocchio::{error::ProgramError, AccountView};
use zolana_account_checks::AccountIterator;
use zolana_interface::{
    error::ShieldedPoolError, instruction::instruction_data::transact::TransactIxDataRef,
};

use crate::instructions::{transact::account::TransactAccounts, zone_config::loader::load_zone_config};

pub struct ZoneTransactAccounts;

impl ZoneTransactAccounts {
    /// Parse the accounts shared by `zone_transact` and `zone_authority_transact`:
    /// `payer`, `tree`, the `ZoneConfig` account (the zone's `zone_auth` PDA), then
    /// the cpi-signer / settlement accounts shared with `transact`. Returns the
    /// parsed transact accounts and the zone's `program_id`, read from the validated
    /// `ZoneConfig` (never re-derived; the create-time `zone_auth` derivation
    /// already bound it). `REQUIRE_ENABLED` additionally requires
    /// `zone_authority_transact_is_enabled` (only `zone_authority_transact` sets it).
    pub fn validate_and_parse<'a, const REQUIRE_ENABLED: bool>(
        accounts: &'a mut [AccountView],
        ix: &TransactIxDataRef<'_>,
    ) -> Result<(TransactAccounts<'a>, [u8; 32]), ProgramError> {
        let mut iter = AccountIterator::new(accounts);
        let payer: &AccountView = iter.next_signer("payer")?;
        let tree = iter.next_mut("tree")?;
        // The `zone_config` must sign (only the zone program can sign for its
        // `zone_auth` PDA); validate owner / discriminator and read the bound zone
        // `program_id`.
        let zone_config = iter.next_signer("zone_config")?;
        let (zone_program_id, enabled) = {
            let config = load_zone_config(zone_config)?;
            (config.program_id.to_bytes(), config.enabled())
        };
        if REQUIRE_ENABLED && !enabled {
            return Err(ShieldedPoolError::ZoneAuthorityTransactDisabled.into());
        }
        let transact_accounts = TransactAccounts::from_iter(iter, ix, payer, tree)?;
        Ok((transact_accounts, zone_program_id))
    }
}
