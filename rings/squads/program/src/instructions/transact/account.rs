//! `transact` account layout, parsed with `AccountIterator`.
//!
//! The recipient viewing key account is consumed only for a transfer. The SPP
//! account list follows unchanged. Access-control checks (signer, account state)
//! stay in the processor.

use pinocchio::{error::ProgramError, AccountView};
use zolana_account_checks::AccountIterator;

/// The `transact` accounts in instruction order. `recipient_vka` is present only
/// for a transfer; `spp_accounts` is the forwarded SPP `ring_transact` /
/// `ring_authority_transact` account list.
pub struct TransactAccounts<'a> {
    pub payer: &'a AccountView,
    pub co_signer: &'a AccountView,
    pub ring_config: &'a AccountView,
    pub sender_vka: &'a AccountView,
    pub recipient_vka: Option<&'a AccountView>,
    pub spp_accounts: &'a [AccountView],
}

impl<'a> TransactAccounts<'a> {
    pub fn validate_and_parse(
        accounts: &'a mut [AccountView],
        is_transfer: bool,
    ) -> Result<Self, ProgramError> {
        let mut iter = AccountIterator::new(accounts);
        let payer = iter.next_account("payer")?;
        let co_signer = iter.next_account("co_signer")?;
        let ring_config = iter.next_account("ring_config")?;
        let sender_vka = iter.next_account("sender_viewing_key_account")?;
        let recipient_vka = iter
            .next_option("recipient_viewing_key_account", is_transfer)?
            .map(|account| &*account);
        let spp_accounts = iter.remaining_unchecked()?;
        Ok(Self {
            payer,
            co_signer,
            ring_config,
            sender_vka,
            recipient_vka,
            spp_accounts,
        })
    }
}
