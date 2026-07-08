//! `execute_proposal` (tag 13): execute a queued proposal, settling through the
//! SPP.

use pinocchio::{
    sysvars::{clock::Clock, Sysvar},
    AccountView, ProgramResult,
};
use zolana_squads_interface::{
    error::SquadsZoneError, instruction::instruction_data::ExecuteProposalIxData,
    ZONE_AUTH_PDA_SEED,
};

use super::execute_account::ExecuteProposalAccounts;
use super::loader::load_proposal;
use crate::instructions::viewing_key_account::loader::load_viewing_key_account;
use crate::instructions::zone_config::loader::load_zone_config;
use crate::shared::{
    close::close_account,
    cpi,
    pda::verify_pda,
    spp_transact::{
        build_spp_zone_transfer_data, build_spp_zone_withdrawal_data, SppSettlementRail,
        SppZoneTransferParams, SppZoneWithdrawalParams,
    },
    withdrawal::{forward_zone_withdrawal, withdrawal_is_spl},
    zone_proof::{zone_recipient, ZoneProof},
};

/// `execute_proposal` (tag 13): execute a queued proposal, settling through the
/// SPP.
///
/// Accounts: `[payer (signer, writable), co_signer (signer), zone_config
/// (readonly), proposal (writable), sender_viewing_key_account (readonly),
/// recipient_viewing_key_account (readonly, transfer only), rent_recipient
/// (writable), zone_auth, spp_program, ..tree_accounts]`.
///
/// Reads `proposal_hash` from the proposal account (not the instruction data) as
/// the zone-proof public input, verifies the zone proof, CPIs the SPP to settle,
/// then closes the proposal and refunds rent to the recorded payer.
#[inline(never)]
pub fn process_execute_proposal_ix(accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    let ix = ExecuteProposalIxData::deserialize(data)
        .map_err(|_| SquadsZoneError::InvalidInstructionData)?;

    // `public_amount` is Some(amount) for a withdrawal (1 output, no recipient
    // viewing key) and None for a transfer (2 outputs, recipient present). The
    // recipient slot is consumed by the parser only for a transfer.
    let is_transfer = ix.public_amount.is_none();
    let accs = ExecuteProposalAccounts::validate_and_parse(accounts, is_transfer)?;

    // Signer checks live in the processor (not nested in helpers).
    if !accs.payer.is_signer() {
        return Err(SquadsZoneError::MissingAuthoritySignature.into());
    }
    if !accs.co_signer.is_signer() {
        return Err(SquadsZoneError::MissingCoSignerSignature.into());
    }

    let zone = load_zone_config(accs.zone_config)?;
    if accs.co_signer.address() != &zone.co_signer {
        return Err(SquadsZoneError::CoSignerMismatch.into());
    }

    let record = load_proposal(accs.proposal)?;

    // The proposal expires once the cluster Unix time passes `expiry`.
    let now = Clock::get()?.unix_timestamp;
    if now > record.expiry {
        return Err(SquadsZoneError::ProposalExpired.into());
    }

    let sender = load_viewing_key_account(accs.sender_vka)?;
    // The proposal is bound to the sender viewing key account's owner field (what
    // `create_proposal` / `cancel_proposal` compare), not the account address.
    if sender.owner != record.owner {
        return Err(SquadsZoneError::ProposalOwnershipMismatch.into());
    }
    if accs.rent_recipient.address() != &record.rent_payer {
        return Err(SquadsZoneError::RentRecipientMismatch.into());
    }

    // `execute_proposal` selects the zone verifying key from the instruction-data
    // vector lengths (`select_zone_vk` rejects unsupported shapes); `transact`
    // hardcodes the shape from the operation instead.
    let n_inputs = u8::try_from(ix.input_contexts.len())
        .map_err(|_| SquadsZoneError::InvalidInstructionData)?;
    let n_outputs = u8::try_from(ix.output_utxo_hashes.len())
        .map_err(|_| SquadsZoneError::InvalidInstructionData)?;

    let public_amount = ix
        .public_amount
        .map(|amount| {
            let mut be = [0u8; 32];
            be[24..].copy_from_slice(&amount.to_be_bytes());
            be
        })
        .unwrap_or([0u8; 32]);

    // The zone circuit hashes the sender and each recipient ciphertext
    // separately, so they are read as typed `EncryptedUtxos` fields (parsed
    // inline with the rest of the instruction data).
    let encrypted_utxos = &ix.encrypted_utxos;
    let sender_ciphertext = encrypted_utxos.sender_ciphertext.as_slice();

    // `recipient_account` is hoisted to the outer scope so its viewing-key borrow
    // in `ZoneRecipient` stays alive through `.verify()` below. The parser already
    // gated the recipient account on the transfer shape; `zone_recipient` then
    // checks the recipient ciphertext count agrees.
    let recipient_account = match accs.recipient_vka {
        Some(recipient_vka) => Some(load_viewing_key_account(recipient_vka)?),
        None => None,
    };
    let recipient = zone_recipient(encrypted_utxos, recipient_account.as_ref())?;

    ZoneProof {
        private_tx_hash: ix.private_tx_hash,
        public_amount,
        sender_owner: sender.owner.to_bytes(),
        sender_commitment: sender.shared_viewing_key_commitment,
        sender_nullifier_pubkey: sender.nullifier_pubkey,
        sender_ciphertext,
        recipient,
        // `proposal_hash` comes from the Proposal account, NOT the instruction
        // data (spec: execute_proposal reads it from the proposal).
        proposal_hash: record.proposal_hash,
        proof: &ix.zone_proof,
        n_inputs,
        n_outputs,
    }
    .verify()?;

    // Settle through the SPP, signed by the zone-auth PDA. The forwarded accounts
    // follow SPP's `zone_transact` order (payer, tree, zone_config == zone_auth),
    // not the zone's own order. Only one tree is ever touched.
    let zone_auth_bump = verify_pda(accs.zone_auth.address(), &[ZONE_AUTH_PDA_SEED], &crate::ID)?;
    let expiry_unix_ts =
        u64::try_from(record.expiry).map_err(|_| SquadsZoneError::InvalidProposal)?;
    // Route smart-account-owned senders through the signatureless zone-authority
    // rail; keypair/P256 senders keep the P256 rail.
    let rail = SppSettlementRail::for_owner_kind(sender.owner_kind);
    if is_transfer {
        let spp_data = build_spp_zone_transfer_data(SppZoneTransferParams {
            expiry_unix_ts,
            private_tx_hash: ix.private_tx_hash,
            spp_proof: &ix.spp_proof,
            salt: ix.salt,
            output_view_tags: &ix.output_view_tags,
            output_utxo_hashes: &ix.output_utxo_hashes,
            input_contexts: &ix.input_contexts,
            encrypted_utxos: &ix.encrypted_utxos,
            rail,
        })?;
        let cpi_accounts: [&AccountView; 4] =
            [accs.payer, accs.tree, accs.zone_auth, accs.spp_program];
        cpi::spp_transact(accs.spp_program, &cpi_accounts, &spp_data, zone_auth_bump)?;
    } else {
        let is_spl = withdrawal_is_spl(accs.settlement)?;
        let amount = ix
            .public_amount
            .ok_or(SquadsZoneError::InvalidInstructionData)?;
        let spp_data = build_spp_zone_withdrawal_data(SppZoneWithdrawalParams {
            expiry_unix_ts,
            private_tx_hash: ix.private_tx_hash,
            spp_proof: &ix.spp_proof,
            salt: ix.salt,
            output_view_tags: &ix.output_view_tags,
            output_utxo_hashes: &ix.output_utxo_hashes,
            input_contexts: &ix.input_contexts,
            encrypted_utxos: &ix.encrypted_utxos,
            amount,
            is_spl,
            rail,
        })?;
        forward_zone_withdrawal(
            accs.spp_program,
            accs.payer,
            accs.tree,
            accs.zone_auth,
            accs.settlement,
            &spp_data,
            zone_auth_bump,
        )?;
    }

    // Close the settled proposal, refunding rent to the recorded rent payer.
    close_account(
        accs.proposal,
        accs.rent_recipient,
        SquadsZoneError::InvalidProposal,
    )
}
