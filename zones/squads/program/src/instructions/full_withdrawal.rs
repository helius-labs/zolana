//! `full_withdrawal` (tag 10): escape-hatch public exit through the SPP without
//! the co-signer or backend.
//!
//! Authorization is the forwarded SPP proof: it proves knowledge of the UTXO's
//! P256 owner secret and binds the recipient/amount, so only the true owner can
//! produce it and no one can redirect it. There is no co-signer and no zone
//! proof. The transaction signer is only a fee payer -- it need NOT be the UTXO
//! owner (the UTXO owner is a P256 identity, not a Solana key), which is also the
//! `payer_pubkey_hash` the SPP proof was generated for. Settlement forwards the
//! SPP proof through SPP's `zone_transact` with a negated public amount, exactly
//! like the `transact` withdrawal leg.

use pinocchio::{
    error::ProgramError,
    sysvars::{clock::Clock, Sysvar},
    AccountView, ProgramResult,
};
use zolana_account_checks::AccountIterator;
use zolana_squads_interface::{
    error::SquadsZoneError, instruction::instruction_data::FullWithdrawalIxData, ZONE_AUTH_PDA_SEED,
};

use crate::shared::{
    pda::verify_pda,
    spp_transact::{build_spp_zone_withdrawal_data, SppSettlementRail, SppZoneWithdrawalParams},
    withdrawal::{forward_zone_withdrawal, withdrawal_is_spl},
};

/// The `full_withdrawal` accounts in instruction order. `settlement` is the
/// SOL/SPL account tail forwarded to SPP.
struct FullWithdrawalAccounts<'a> {
    payer: &'a AccountView,
    zone_auth: &'a AccountView,
    spp_program: &'a AccountView,
    tree: &'a AccountView,
    settlement: &'a [AccountView],
}

impl<'a> FullWithdrawalAccounts<'a> {
    fn validate_and_parse(accounts: &'a mut [AccountView]) -> Result<Self, ProgramError> {
        let mut iter = AccountIterator::new(accounts);
        let payer = iter.next_account("payer")?;
        let zone_auth = iter.next_account("zone_auth")?;
        let spp_program = iter.next_account("spp_program")?;
        let tree = iter.next_account("tree")?;
        let settlement = iter.remaining_unchecked()?;
        Ok(Self {
            payer,
            zone_auth,
            spp_program,
            tree,
            settlement,
        })
    }
}

/// `full_withdrawal` (tag 10): escape-hatch public exit. The forwarded SPP proof
/// is the authorization (P256 UTXO ownership); there is no co-signer and no zone
/// proof. The signer is only a fee payer and is forwarded as SPP's payer (bound
/// in the proof's `payer_pubkey_hash`).
#[inline(never)]
pub fn process_full_withdrawal_ix(accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    let ix = FullWithdrawalIxData::deserialize(data)
        .map_err(|_| SquadsZoneError::InvalidInstructionData)?;

    let accs = FullWithdrawalAccounts::validate_and_parse(accounts)?;

    // The signer is only the fee payer; the SPP proof authorizes the spend, so
    // there is no owner-signature check (the UTXO owner is a P256 identity, not a
    // Solana key) and no co-signer.
    if !accs.payer.is_signer() {
        return Err(SquadsZoneError::MissingAuthoritySignature.into());
    }

    // Reject an expired settlement against the cluster clock.
    let now = Clock::get()?.unix_timestamp;
    if now > ix.expiry {
        return Err(SquadsZoneError::TransactionExpired.into());
    }

    let zone_auth_bump = verify_pda(accs.zone_auth.address(), &[ZONE_AUTH_PDA_SEED], &crate::ID)?;
    let is_spl = withdrawal_is_spl(accs.settlement)?;
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
        is_spl,
        // The escape hatch is always a P256-owned UTXO (no smart-account VKA).
        rail: SppSettlementRail::P256,
    })?;

    forward_zone_withdrawal(
        accs.spp_program,
        accs.payer,
        accs.tree,
        accs.zone_auth,
        accs.settlement,
        &spp_data,
        zone_auth_bump,
    )
}
