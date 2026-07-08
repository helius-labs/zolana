//! `execute_proposal` account layout, parsed with `AccountIterator` (mirrors the
//! SPP `TransactAccounts::validate_and_parse` pattern).
//!
//! Like `transact`, the recipient viewing key account is consumed only for a
//! transfer, so the withdrawal and transfer layouts both line up with the builder
//! without a placeholder slot. `proposal` and `rent_recipient` are kept mutable
//! for the closing refund. Access-control checks stay in the processor.

use pinocchio::{error::ProgramError, AccountView};
use zolana_account_checks::AccountIterator;

/// The `execute_proposal` accounts in instruction order.
pub struct ExecuteProposalAccounts<'a> {
    pub payer: &'a AccountView,
    pub co_signer: &'a AccountView,
    pub zone_config: &'a AccountView,
    pub proposal: &'a mut AccountView,
    pub sender_vka: &'a AccountView,
    pub recipient_vka: Option<&'a AccountView>,
    pub rent_recipient: &'a mut AccountView,
    pub zone_auth: &'a AccountView,
    pub spp_program: &'a AccountView,
    pub tree: &'a AccountView,
    pub settlement: &'a [AccountView],
}

impl<'a> ExecuteProposalAccounts<'a> {
    /// Parse the accounts in order, consuming the `recipient_vka` slot only when
    /// `is_transfer` (derived from `public_amount`).
    pub fn validate_and_parse(
        accounts: &'a mut [AccountView],
        is_transfer: bool,
    ) -> Result<Self, ProgramError> {
        let mut iter = AccountIterator::new(accounts);
        let payer = iter.next_account("payer")?;
        let co_signer = iter.next_account("co_signer")?;
        let zone_config = iter.next_account("zone_config")?;
        let proposal = iter.next_account("proposal")?;
        let sender_vka = iter.next_account("sender_viewing_key_account")?;
        let recipient_vka = iter
            .next_option("recipient_viewing_key_account", is_transfer)?
            .map(|account| &*account);
        let rent_recipient = iter.next_account("rent_recipient")?;
        let zone_auth = iter.next_account("zone_auth")?;
        let spp_program = iter.next_account("spp_program")?;
        let tree = iter.next_account("tree")?;
        let settlement = iter.remaining_unchecked()?;
        Ok(Self {
            payer,
            co_signer,
            zone_config,
            proposal,
            sender_vka,
            recipient_vka,
            rent_recipient,
            zone_auth,
            spp_program,
            tree,
            settlement,
        })
    }
}
