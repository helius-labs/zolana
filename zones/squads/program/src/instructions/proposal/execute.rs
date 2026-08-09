use pinocchio::{
    sysvars::{clock::Clock, Sysvar},
    AccountView, ProgramResult,
};
use zolana_squads_interface::{
    constants::VIEWING_KEY_STATE_ACTIVE, error::SquadsZoneError,
    instruction::instruction_data::ExecuteProposalIxData, types::Address, RING_AUTH_PDA_SEED,
};

use super::commitment::{proposal_commitment_hash, verify_execution_context, ProposalOperation};
use super::execute_account::ExecuteProposalAccounts;
use super::loader::load_proposal;
use crate::instructions::viewing_key_account::loader::load_viewing_key_account;
use crate::instructions::zone_config::loader::load_zone_config;
use crate::shared::{
    close::close_account,
    cpi,
    pda::verify_pda,
    shapes::operation_shape,
    spp_transact::{
        build_spp_zone_transfer_data, build_spp_zone_withdrawal_data, SppSettlementRail,
        SppZoneTransferParams, SppZoneWithdrawalParams,
    },
    withdrawal::{forward_zone_withdrawal, withdrawal_settlement, WithdrawalSettlement},
    zone_proof::{public_amount_fe, zone_recipient, ZoneProof},
};

/// `execute_proposal` (tag 13): execute a queued proposal, settling through the
/// SPP.
///
/// Accounts: `[payer (signer, writable), co_signer (signer), zone_config
/// (readonly), proposal (writable), sender_viewing_key_account (readonly),
/// recipient_viewing_key_account (readonly, transfer only), rent_recipient
/// (writable), ring_auth, spp_program, ..tree_accounts]`.
///
/// Reads the private proposal core from the proposal account, combines it with
/// the checked operation, asset, and destination to reconstruct the zone-proof
/// public commitment, verifies the proof, CPIs the SPP to settle, then closes
/// the proposal and refunds rent to the recorded payer.
#[inline(never)]
pub fn process_execute_proposal_ix(accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    let ix = ExecuteProposalIxData::deserialize(data)
        .map_err(|_| SquadsZoneError::InvalidInstructionData)?;

    let is_transfer = ix.public_amount.is_none();
    let accs = ExecuteProposalAccounts::validate_and_parse(accounts, is_transfer)?;

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

    let now = Clock::get()?.unix_timestamp;
    if now > record.expiry {
        return Err(SquadsZoneError::ProposalExpired.into());
    }

    let sender = load_viewing_key_account(accs.sender_vka)?;
    if sender.state != VIEWING_KEY_STATE_ACTIVE {
        return Err(SquadsZoneError::ViewingKeyAccountBlocked.into());
    }
    // The proposal is bound to the sender viewing key account's owner field (what
    // `create_proposal` / `cancel_proposal` compare), not the account address.
    if sender.owner != record.owner {
        return Err(SquadsZoneError::ProposalOwnershipMismatch.into());
    }
    if accs.rent_recipient.address() != &record.rent_payer {
        return Err(SquadsZoneError::RentRecipientMismatch.into());
    }

    // The operation names the shape here exactly as it does in `transact`, so
    // the caller cannot select a different verifying key by padding a vector.
    let (n_inputs, n_outputs) = operation_shape(
        is_transfer,
        ix.input_contexts.len(),
        ix.output_utxo_hashes.len(),
    )?;

    let public_amount = public_amount_fe(ix.public_amount);

    let encrypted_utxos = &ix.encrypted_utxos;
    let sender_ciphertext = encrypted_utxos.sender_ciphertext.as_slice();

    let recipient_account = match accs.recipient_vka {
        Some(recipient_vka) => {
            let recipient = load_viewing_key_account(recipient_vka)?;
            if recipient.state != VIEWING_KEY_STATE_ACTIVE {
                return Err(SquadsZoneError::ViewingKeyAccountBlocked.into());
            }
            Some(recipient)
        }
        None => None,
    };
    let recipient = zone_recipient(encrypted_utxos, recipient_account.as_ref())?;

    let withdrawal = if is_transfer {
        None
    } else {
        Some(withdrawal_settlement(
            accs.settlement,
            ix.spl_interface_bump,
        )?)
    };

    let operation = match withdrawal {
        None => {
            let recipient_account = recipient_account
                .as_ref()
                .ok_or(SquadsZoneError::InvalidInstructionData)?;
            verify_execution_context(&record, record.asset, recipient_account.owner)?;
            ProposalOperation::Transfer
        }
        Some(settlement) => {
            let (asset, destination) = match settlement {
                // SPP SPL withdrawal tail: cpi_authority, mint, spl_interface,
                // destination token account, token_program.
                WithdrawalSettlement::Spl { .. } => {
                    let mint = accs
                        .settlement
                        .get(1)
                        .ok_or(SquadsZoneError::InvalidWithdrawalAccounts)?;
                    let destination = accs
                        .settlement
                        .get(3)
                        .ok_or(SquadsZoneError::InvalidWithdrawalAccounts)?;
                    (*mint.address(), *destination.address())
                }
                // SPP SOL withdrawal tail: sol_interface, destination,
                // system_program. SOL uses the default mint address.
                WithdrawalSettlement::Sol => {
                    let destination = accs
                        .settlement
                        .get(1)
                        .ok_or(SquadsZoneError::InvalidWithdrawalAccounts)?;
                    (Address::default(), *destination.address())
                }
            };
            verify_execution_context(&record, asset, destination)?;
            ProposalOperation::Withdrawal
        }
    };
    let proposal_commitment = proposal_commitment_hash(&record, operation)?;

    ZoneProof {
        private_tx_hash: ix.private_tx_hash,
        public_amount,
        sender_owner: sender.owner.to_bytes(),
        sender_commitment: sender.shared_viewing_key_commitment,
        sender_nullifier_pubkey: sender.nullifier_pubkey,
        sender_ciphertext,
        recipient,
        proposal_hash: proposal_commitment,
        proof: &ix.zone_proof,
        n_inputs,
        n_outputs,
    }
    .verify()?;

    let ring_auth_bump = verify_pda(accs.ring_auth.address(), &[RING_AUTH_PDA_SEED], &crate::ID)?;
    let expiry_unix_ts =
        u64::try_from(record.expiry).map_err(|_| SquadsZoneError::InvalidProposal)?;
    let rail = SppSettlementRail::for_owner_kind(sender.kind()?);
    match withdrawal {
        None => {
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
                [accs.payer, accs.tree, accs.ring_auth, accs.spp_program];
            cpi::spp_transact(accs.spp_program, &cpi_accounts, &spp_data, ring_auth_bump)?;
        }
        Some(settlement) => {
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
                settlement,
                rail,
            })?;
            forward_zone_withdrawal(
                accs.spp_program,
                accs.payer,
                accs.tree,
                accs.ring_auth,
                accs.settlement,
                &spp_data,
                ring_auth_bump,
            )?;
        }
    }

    close_account(
        accs.proposal,
        accs.rent_recipient,
        SquadsZoneError::InvalidProposal,
    )
}
