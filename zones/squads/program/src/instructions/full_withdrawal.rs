//! `full_withdrawal` (tag 10): escape-hatch public exit through the SPP without
//! the co-signer or backend.
//!
//! The forwarded SPP proof is the authorization. It proves knowledge of the
//! UTXO's P256 owner secret and binds the recipient and the amount, so only the
//! owner can produce it and nobody can redirect it. There is no co-signer and no
//! zone proof. The transaction signer is only a fee payer, bound by the proof as
//! `payer_pubkey_hash`. Settlement forwards the proof through SPP's
//! `zone_transact` with a negated public amount.

use pinocchio::{
    error::ProgramError,
    sysvars::{clock::Clock, Sysvar},
    AccountView, ProgramResult,
};
use zolana_account_checks::AccountIterator;
use zolana_squads_interface::{
    error::SquadsZoneError, instruction::instruction_data::FullWithdrawalIxData, RING_AUTH_PDA_SEED,
};

use crate::shared::{
    pda::verify_pda,
    spp_transact::{build_spp_zone_withdrawal_data, SppSettlementRail, SppZoneWithdrawalParams},
    withdrawal::{forward_zone_withdrawal, withdrawal_settlement},
};

/// The `full_withdrawal` accounts in instruction order. `settlement` is the
/// SOL/SPL account tail forwarded to SPP.
struct FullWithdrawalAccounts<'a> {
    payer: &'a AccountView,
    ring_auth: &'a AccountView,
    spp_program: &'a AccountView,
    tree: &'a AccountView,
    settlement: &'a [AccountView],
}

impl<'a> FullWithdrawalAccounts<'a> {
    fn validate_and_parse(accounts: &'a mut [AccountView]) -> Result<Self, ProgramError> {
        let mut iter = AccountIterator::new(accounts);
        let payer = iter.next_account("payer")?;
        let ring_auth = iter.next_account("ring_auth")?;
        let spp_program = iter.next_account("spp_program")?;
        let tree = iter.next_account("tree")?;
        let settlement = iter.remaining_unchecked()?;
        Ok(Self {
            payer,
            ring_auth,
            spp_program,
            tree,
            settlement,
        })
    }
}

#[inline(never)]
pub fn process_full_withdrawal_ix(accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    let ix = FullWithdrawalIxData::deserialize(data)
        .map_err(|_| SquadsZoneError::InvalidInstructionData)?;

    let accs = FullWithdrawalAccounts::validate_and_parse(accounts)?;

    if !accs.payer.is_signer() {
        return Err(SquadsZoneError::MissingAuthoritySignature.into());
    }

    let now = Clock::get()?.unix_timestamp;
    if now > ix.expiry {
        return Err(SquadsZoneError::TransactionExpired.into());
    }

    let ring_auth_bump = verify_pda(accs.ring_auth.address(), &[RING_AUTH_PDA_SEED], &crate::ID)?;
    let settlement = withdrawal_settlement(accs.settlement, ix.spl_interface_bump)?;
    let expiry_unix_ts =
        u64::try_from(ix.expiry).map_err(|_| SquadsZoneError::InvalidInstructionData)?;

    let spp_data = build_spp_zone_withdrawal_data(SppZoneWithdrawalParams {
        expiry_unix_ts,
        private_tx_hash: ix.private_tx_hash,
        spp_proof: &ix.spp_proof,
        salt: ix.salt,
        output_view_tags: &ix.output_view_tags,
        output_utxo_hashes: &ix.output_utxo_hashes,
        input_contexts: &ix.input_contexts,
        encrypted_utxos: &ix.encrypted_utxos,
        amount: ix.public_amount,
        settlement,
        // The escape hatch is always a P256-owned UTXO (no smart-account VKA).
        rail: SppSettlementRail::P256,
    })?;

    forward_zone_withdrawal(
        accs.spp_program,
        accs.payer,
        accs.tree,
        accs.ring_auth,
        accs.settlement,
        &spp_data,
        ring_auth_bump,
    )
}
