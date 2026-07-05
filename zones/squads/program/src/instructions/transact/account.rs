//! `transact` account layout, parsed with `AccountIterator` (mirrors the SPP
//! `TransactAccounts::validate_and_parse` pattern).
//!
//! The recipient viewing key account is consumed only for a transfer; a
//! withdrawal instead appends the SPP settlement accounts after the tree. Access-
//! control checks (signer, account state) stay in the processor.

use pinocchio::{error::ProgramError, AccountView};
use zolana_account_checks::AccountIterator;

/// The `transact` accounts in instruction order. `recipient_vka` is present only
/// for a transfer; `settlement` is the SOL/SPL account tail present only for a
/// withdrawal. Exactly one `tree` is ever touched.
pub struct TransactAccounts<'a> {
    pub payer: &'a AccountView,
    pub co_signer: &'a AccountView,
    pub zone_config: &'a AccountView,
    pub sender_vka: &'a AccountView,
    pub recipient_vka: Option<&'a AccountView>,
    pub zone_auth: &'a AccountView,
    pub spp_program: &'a AccountView,
    pub tree: &'a AccountView,
    pub settlement: &'a [AccountView],
}

impl<'a> TransactAccounts<'a> {
    /// Parse the accounts in order, consuming the `recipient_vka` slot only when
    /// `is_transfer` (derived from `public_amount`). The remaining accounts after
    /// the tree are the withdrawal settlement tail (empty for a transfer).
    pub fn validate_and_parse(
        accounts: &'a mut [AccountView],
        is_transfer: bool,
    ) -> Result<Self, ProgramError> {
        let mut iter = AccountIterator::new(accounts);
        let payer = iter.next_account("payer")?;
        let co_signer = iter.next_account("co_signer")?;
        let zone_config = iter.next_account("zone_config")?;
        let sender_vka = iter.next_account("sender_viewing_key_account")?;
        let recipient_vka = iter
            .next_option("recipient_viewing_key_account", is_transfer)?
            .map(|account| &*account);
        let zone_auth = iter.next_account("zone_auth")?;
        let spp_program = iter.next_account("spp_program")?;
        let tree = iter.next_account("tree")?;
        let settlement = iter.remaining_unchecked()?;
        Ok(Self {
            payer,
            co_signer,
            zone_config,
            sender_vka,
            recipient_vka,
            zone_auth,
            spp_program,
            tree,
            settlement,
        })
    }
}
