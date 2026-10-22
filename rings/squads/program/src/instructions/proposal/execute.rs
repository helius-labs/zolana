//! `execute_proposal` (tag 13): execute a queued proposal, settling through the
//! SPP.

use pinocchio::{
    sysvars::{clock::Clock, Sysvar},
    AccountView, ProgramResult,
};
use zolana_squads_interface::{
    error::SquadsRingError, instruction::instruction_data::ExecuteProposalIxData,
};

use super::execute_account::ExecuteProposalAccounts;
use super::loader::load_proposal;
use crate::instructions::ring_config::loader::load_ring_config;
use crate::instructions::viewing_key_account::loader::load_viewing_key_account;
use crate::shared::{
    close::close_account,
    cpi::forward_to_spp,
    ring_proof::{ring_recipient, RingProof},
    spp_transact::{external_data_hash, forwarded_spp_data, SppSettlementRail, SppTransact},
};

/// `execute_proposal` (tag 13): execute a queued proposal, settling through the
/// SPP.
///
/// Accounts: `[payer (signer, writable), co_signer (signer), ring_config
/// (readonly), proposal (writable), sender_viewing_key_account (readonly),
/// recipient_viewing_key_account (readonly, transfer only), rent_recipient
/// (writable), ..spp_accounts]`.
///
/// Reads `proposal_hash` from the proposal account (not the instruction data) as
/// the ring-proof public input, verifies the ring proof, CPIs the SPP to settle,
/// then closes the proposal and refunds rent to the recorded payer.
#[inline(never)]
pub fn process_execute_proposal_ix(accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    let ix = decode(data)?;
    let spp = SppTransact::parse(&ix.spp)?;

    let accs = ExecuteProposalAccounts::validate_and_parse(accounts, spp.is_transfer())?;

    // Signer checks live in the processor (not nested in helpers).
    if !accs.payer.is_signer() {
        return Err(SquadsRingError::MissingAuthoritySignature.into());
    }
    if !accs.co_signer.is_signer() {
        return Err(SquadsRingError::MissingCoSignerSignature.into());
    }

    let ring = load_ring_config(accs.ring_config)?;
    if accs.co_signer.address() != &ring.co_signer {
        return Err(SquadsRingError::CoSignerMismatch.into());
    }

    let record = load_proposal(accs.proposal)?;

    // The proposal expires once the cluster Unix time passes `expiry`, and the
    // settlement must not outlive it.
    let now = Clock::get()?.unix_timestamp;
    if now > record.expiry {
        return Err(SquadsRingError::ProposalExpired.into());
    }
    let expiry_unix_ts =
        u64::try_from(record.expiry).map_err(|_| SquadsRingError::InvalidProposal)?;
    if ix.spp.expiry_unix_ts != expiry_unix_ts {
        return Err(SquadsRingError::InvalidInstructionData.into());
    }

    let sender = load_viewing_key_account(accs.sender_vka)?;
    // The proposal is bound to the sender viewing key account's owner field (what
    // `create_proposal` / `cancel_proposal` compare), not the account address.
    if sender.owner != record.owner {
        return Err(SquadsRingError::ProposalOwnershipMismatch.into());
    }
    if accs.rent_recipient.address() != &record.rent_payer {
        return Err(SquadsRingError::RentRecipientMismatch.into());
    }

    // Route smart-account-owned senders through the signatureless ring-authority
    // rail; keypair/Ed25519 senders keep the Ed25519 rail.
    let rail = SppSettlementRail::for_owner_kind(sender.owner_kind);
    rail.check_circuit(&ix.spp.circuit)?;

    let recipient_account = match accs.recipient_vka {
        Some(recipient_vka) => Some(load_viewing_key_account(recipient_vka)?),
        None => None,
    };
    let recipient = ring_recipient(
        &ix.spp.tx_viewing_pk,
        spp.recipient_ciphertext()?,
        recipient_account.as_ref(),
    )?;
    let (n_inputs, n_outputs) = spp.shape();
    RingProof {
        private_tx_hash: ix.spp.private_tx_hash,
        external_data_hash: external_data_hash(rail, data, accs.spp_accounts)?,
        public_amount: spp.public_amount_field(),
        sender_owner: sender.owner.to_bytes(),
        sender_commitment: sender.shared_viewing_key_commitment,
        sender_nullifier_pubkey: sender.nullifier_pubkey,
        sender_ciphertext: spp.sender_ciphertext()?,
        recipient,
        // `proposal_hash` comes from the Proposal account, NOT the instruction
        // data (spec: execute_proposal reads it from the proposal).
        proposal_hash: record.proposal_hash,
        proof: &ix.ring_proof,
        n_inputs,
        n_outputs,
    }
    .verify()?;

    forward_to_spp(accs.spp_accounts, &forwarded_spp_data(rail, data)?)?;

    close_account(
        accs.proposal,
        accs.rent_recipient,
        SquadsRingError::InvalidProposal,
    )
}

#[inline(never)]
fn decode(data: &[u8]) -> Result<Box<ExecuteProposalIxData>, SquadsRingError> {
    ExecuteProposalIxData::deserialize(data)
        .map(Box::new)
        .map_err(|_| SquadsRingError::InvalidInstructionData)
}
